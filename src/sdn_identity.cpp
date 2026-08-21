#include "hd_wallet/sdn_identity.h"

#include "canonical_json.h"
#include "password_profile_internal.h"
#include "sdn_identity_internal.h"

#include <cryptopp/cryptlib.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace hd_wallet::sdn {
namespace {

using internal::DerivedIdentityMaterial;
using internal::IdentityKind;
using internal::SecretBuffer;
using jcs::Value;

constexpr size_t kIdentitySlots = 16;
constexpr std::string_view kSignatureProfile =
    "ed25519-over-sha256-jcs-v1";
constexpr std::string_view kRawSignatureProfile = "ed25519-raw-32-v1";
constexpr std::string_view kStorageProfile =
    "webauthn-prf-hkdf-sha256-aes256gcm-v2";
constexpr std::string_view kRememberInfo = "hd-wallet-ui/remember-wallet-v2";

struct RegistryRow {
    RegistryRowId id;
    RegisteredOperation operation;
    std::string_view client_id;
    std::string_view request_origin;
    std::string_view audience;
    std::string_view service_instance;
    uint32_t maximum_lifetime_seconds;
};

constexpr std::array<RegistryRow, 3> kRegistryRows = {{
    {RegistryRowId::SdnNodeConsoleV2, RegisteredOperation::SdnLoginV2,
     "sdn-node-console-v1", "https://sdn.spaceaware.io",
     "sdn-login:sdn.spaceaware.io", "", 300},
    {RegistryRowId::AssetReviewAuthorityActivation,
     RegisteredOperation::AssetReviewAuthorityActivation,
     "sdn-asset-review-v1", "https://review.spacedatanetwork.org",
     "asset-review-authority:assets.ipfs.01",
     "assets.ipfs.01/asset-review-attestation", 300},
    {RegistryRowId::AssetReviewDecision,
     RegisteredOperation::AssetReviewDecision,
     "sdn-asset-review-v1", "https://review.spacedatanetwork.org",
     "asset-review:assets.ipfs.01", "", 300},
}};

const RegistryRow* registryRow(RegistryRowId id) {
    const auto found = std::find_if(kRegistryRows.begin(), kRegistryRows.end(),
                                    [id](const RegistryRow& row) {
                                        return row.id == id;
                                    });
    return found == kRegistryRows.end() ? nullptr : &*found;
}

struct IdentityRecord {
    std::string canonical_username;
    DerivedIdentityMaterial material;
    PublicIdentity public_identity;

    IdentityRecord(std::string username,
                   DerivedIdentityMaterial&& secret_material,
                   PublicIdentity&& identity)
        : canonical_username(std::move(username)),
          material(std::move(secret_material)),
          public_identity(std::move(identity)) {}
    IdentityRecord(const IdentityRecord&) = delete;
    IdentityRecord& operator=(const IdentityRecord&) = delete;
    IdentityRecord(IdentityRecord&&) noexcept = default;
    IdentityRecord& operator=(IdentityRecord&&) noexcept = default;
};

static_assert(!std::is_copy_constructible_v<IdentityRecord>);
static_assert(!std::is_copy_assignable_v<IdentityRecord>);
static_assert(std::is_nothrow_move_constructible_v<IdentityRecord>);
static_assert(std::is_nothrow_move_assignable_v<IdentityRecord>);

struct Slot {
    uint32_t generation{1};
    bool retired{false};
    std::optional<IdentityRecord> record;
};

std::array<Slot, kIdentitySlots> g_slots;
std::mutex g_slots_mutex;

std::span<const uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}

std::string hex(std::span<const uint8_t> input) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output(input.size() * 2, '\0');
    for (size_t i = 0; i < input.size(); ++i) {
        output[2 * i] = alphabet[input[i] >> 4];
        output[2 * i + 1] = alphabet[input[i] & 0x0f];
    }
    return output;
}

std::string keyId(std::span<const uint8_t> public_key) {
    const auto digest = internal::sha256_public(public_key);
    return "sha256:" + hex(digest);
}

IdentityError mapPasswordError(PasswordError error) {
    switch (error) {
        case PasswordError::InvalidUsername:
            return IdentityError::InvalidUsername;
        case PasswordError::CommonPassword:
            return IdentityError::CommonPassword;
        case PasswordError::KdfFailure:
            return IdentityError::KdfFailure;
        case PasswordError::InvalidPasswordScalar:
        case PasswordError::InvalidUtf8:
        case PasswordError::PasswordLength:
        case PasswordError::PasswordByteLength:
        case PasswordError::PasswordAllWhitespace:
            return IdentityError::InvalidPassword;
    }
    return IdentityError::CryptoFailure;
}

PublicKeyDescriptor descriptor(Purpose purpose,
                               std::string_view scheme,
                               std::string_view profile,
                               std::optional<std::string> signature_profile,
                               Curve curve,
                               KeyDerivation derivation,
                               std::string path,
                               std::span<const uint8_t> public_key) {
    PublicKeyDescriptor result{
        purpose,
        std::string(scheme),
        std::string(profile),
        std::move(signature_profile),
        curve,
        derivation,
        std::move(path),
        KeyEncoding::Raw,
        std::vector<uint8_t>(public_key.begin(), public_key.end()),
        std::nullopt,
        keyId(public_key),
    };
    return result;
}

PublicIdentity buildPublicIdentity(const DerivedIdentityMaterial& material) {
    const bool modern = material.kind == IdentityKind::PasswordV2;
    const std::string_view scheme = modern
                                        ? kIdentityScheme
                                        : (material.kind == IdentityKind::LegacyPassword
                                               ? kLegacyFastIdentityScheme
                                               : kLegacyMnemonicIdentityScheme);
    const std::string_view profile = modern
                                         ? kPasswordProfile
                                         : (material.kind == IdentityKind::LegacyPassword
                                                ? kLegacyPasswordProfile
                                                : kLegacyMnemonicSeedProfile);
    PublicIdentity identity{
        1,
        std::string(scheme),
        std::string(profile),
        material.account_index,
        std::nullopt,
        material.account_xpub,
        material.account_peer_id,
        material.account_fingerprint,
        {},
    };
    const std::string prefix = "m/44'/0'/" +
                               std::to_string(material.account_index) + "'/";
    if (modern) {
        identity.keys.reserve(3);
        identity.keys.push_back(descriptor(
            Purpose::AssetReviewApproval, scheme, profile,
            std::string(kSignatureProfile), Curve::ED25519,
            KeyDerivation::Slip10Ed25519, prefix + "2'/0'",
            material.approval_public));
        identity.keys.push_back(descriptor(
            Purpose::ContactEncryption, scheme, profile, std::nullopt,
            Curve::X25519, KeyDerivation::Slip10X25519, prefix + "1'/0'",
            material.contact_public));
        identity.keys.push_back(descriptor(
            Purpose::SdnAuthentication, scheme, profile,
            std::string(kSignatureProfile), Curve::ED25519,
            KeyDerivation::Slip10Ed25519, prefix + "0'/0'",
            material.authentication_public));
    } else {
        identity.keys.push_back(descriptor(
            Purpose::SdnAuthentication, scheme, profile,
            std::string(kRawSignatureProfile), Curve::ED25519,
            KeyDerivation::LegacyBip32ScalarAsEd25519Seed, prefix + "0/0",
            material.authentication_public));
    }
    return identity;
}

IdentityOutcome<IdentityHandle> insertRecord(IdentityRecord&& record) {
    std::lock_guard lock(g_slots_mutex);
    for (size_t i = 0; i < g_slots.size(); ++i) {
        auto& slot = g_slots[i];
        if (!slot.retired && !slot.record.has_value()) {
            slot.record.emplace(std::move(record));
            return (static_cast<uint64_t>(slot.generation) << 32) |
                   static_cast<uint64_t>(i + 1);
        }
    }
    return IdentityError::CapacityExceeded;
}

IdentityRecord* lookupLocked(IdentityHandle handle) {
    const uint32_t one_based_slot = static_cast<uint32_t>(handle);
    const uint32_t generation = static_cast<uint32_t>(handle >> 32);
    if (generation == 0 || one_based_slot == 0 || one_based_slot > g_slots.size()) {
        return nullptr;
    }
    auto& slot = g_slots[one_based_slot - 1];
    if (slot.retired || slot.generation != generation || !slot.record.has_value()) {
        return nullptr;
    }
    return &*slot.record;
}

template <typename T, typename Function>
IdentityOutcome<T> safeOutcome(Function&& function) {
    try {
        return function();
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (const CryptoPP::Exception&) {
        return IdentityError::CryptoFailure;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

template <typename MaterialDeriver>
IdentityOutcome<IdentityHandle> insertRawSeed(
    SecretBuffer&& seed,
    IdentityKind kind,
    uint32_t account_index,
    std::string canonical_username,
    MaterialDeriver&& derive_material) {
    auto material = derive_material(std::move(seed), kind, account_index);
    auto identity = buildPublicIdentity(material);
    return insertRecord(IdentityRecord(std::move(canonical_username),
                                       std::move(material),
                                       std::move(identity)));
}

template <typename MaterialDeriver>
IdentityOutcome<ImportedIdentity> insertRawSeedImported(
    SecretBuffer&& seed,
    IdentityKind kind,
    uint32_t account_index,
    std::string canonical_username,
    MaterialDeriver&& derive_material) {
    auto material = derive_material(std::move(seed), kind, account_index);
    auto identity = buildPublicIdentity(material);
    PublicIdentity result_identity = identity;
    auto inserted = insertRecord(IdentityRecord(std::move(canonical_username),
                                                std::move(material),
                                                std::move(identity)));
    if (std::holds_alternative<IdentityError>(inserted)) {
        return std::get<IdentityError>(inserted);
    }
    return ImportedIdentity{std::get<IdentityHandle>(inserted),
                            std::move(result_identity)};
}

bool isLowerHex(std::string_view value, size_t size) {
    return value.size() == size &&
           std::all_of(value.begin(), value.end(), [](char byte) {
               return (byte >= '0' && byte <= '9') ||
                      (byte >= 'a' && byte <= 'f');
           });
}

bool validString(std::string_view value) {
    return jcs::valid_ijson_string(value);
}

bool digit(char value) { return value >= '0' && value <= '9'; }

int parseDigits(std::string_view value, size_t offset, size_t count) {
    int result = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!digit(value[offset + i])) return -1;
        result = result * 10 + value[offset + i] - '0';
    }
    return result;
}

int64_t daysFromCivil(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);
    const unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 +
                         day - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int>(doe) - 719468;
}

std::optional<int64_t> timestampMillis(std::string_view value) {
    if (value.size() != 24 || value[4] != '-' || value[7] != '-' ||
        value[10] != 'T' || value[13] != ':' || value[16] != ':' ||
        value[19] != '.' || value[23] != 'Z') {
        return std::nullopt;
    }
    const int year = parseDigits(value, 0, 4);
    const int month = parseDigits(value, 5, 2);
    const int day = parseDigits(value, 8, 2);
    const int hour = parseDigits(value, 11, 2);
    const int minute = parseDigits(value, 14, 2);
    const int second = parseDigits(value, 17, 2);
    const int millisecond = parseDigits(value, 20, 3);
    if (year < 1 || month < 1 || month > 12 || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 59 ||
        millisecond < 0) {
        return std::nullopt;
    }
    static constexpr int month_days[] = {31, 28, 31, 30, 31, 30,
                                         31, 31, 30, 31, 30, 31};
    int maximum_day = month_days[month - 1];
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if (month == 2 && leap) ++maximum_day;
    if (day < 1 || day > maximum_day) return std::nullopt;
    return (((daysFromCivil(year, static_cast<unsigned>(month),
                            static_cast<unsigned>(day)) * 24 + hour) *
                 60 +
             minute) *
                60 +
            second) *
               1000 +
           millisecond;
}

bool validLifetime(std::string_view issued_at,
                   std::string_view expires_at,
                   uint32_t maximum_seconds) {
    const auto issued = timestampMillis(issued_at);
    const auto expires = timestampMillis(expires_at);
    return issued.has_value() && expires.has_value() && *expires > *issued &&
           *expires - *issued <= static_cast<int64_t>(maximum_seconds) * 1000;
}

bool isTrimScalar(uint32_t scalar) {
    return (scalar >= 0x09 && scalar <= 0x0d) || scalar == 0x20 ||
           scalar == 0x00a0 || scalar == 0x1680 ||
           (scalar >= 0x2000 && scalar <= 0x200a) || scalar == 0x2028 ||
           scalar == 0x2029 || scalar == 0x202f || scalar == 0x205f ||
           scalar == 0x3000 || scalar == 0xfeff;
}

bool decodeScalar(std::string_view value, size_t& position, uint32_t& scalar) {
    const auto* input = reinterpret_cast<const uint8_t*>(value.data());
    if (position >= value.size()) return false;
    const uint8_t first = input[position++];
    size_t continuation = 0;
    if (first <= 0x7f) {
        scalar = first;
    } else if (first >= 0xc2 && first <= 0xdf) {
        scalar = first & 0x1f;
        continuation = 1;
    } else if (first >= 0xe0 && first <= 0xef) {
        if (position >= value.size()) return false;
        const uint8_t second = input[position];
        if ((first == 0xe0 && second < 0xa0) ||
            (first == 0xed && second >= 0xa0)) return false;
        scalar = first & 0x0f;
        continuation = 2;
    } else if (first >= 0xf0 && first <= 0xf4) {
        if (position >= value.size()) return false;
        const uint8_t second = input[position];
        if ((first == 0xf0 && second < 0x90) ||
            (first == 0xf4 && second >= 0x90)) return false;
        scalar = first & 0x07;
        continuation = 3;
    } else {
        return false;
    }
    if (value.size() - position < continuation) return false;
    for (size_t i = 0; i < continuation; ++i) {
        const uint8_t next = input[position++];
        if ((next & 0xc0) != 0x80) return false;
        scalar = (scalar << 6) | (next & 0x3f);
    }
    return true;
}

bool strictUtf8(std::span<const uint8_t> value) {
    const std::string_view view(reinterpret_cast<const char*>(value.data()),
                                value.size());
    size_t position = 0;
    while (position < view.size()) {
        uint32_t scalar = 0;
        if (!decodeScalar(view, position, scalar)) return false;
    }
    return true;
}

bool trimmedText(const std::optional<std::string>& text, bool allow_null) {
    if (!text.has_value()) return allow_null;
    if (text->empty() || text->size() > 2000 || !validString(*text)) return false;
    size_t position = 0;
    uint32_t first = 0;
    uint32_t last = 0;
    bool any = false;
    while (position < text->size()) {
        uint32_t scalar = 0;
        if (!decodeScalar(*text, position, scalar)) return false;
        if (!any) first = scalar;
        last = scalar;
        any = true;
    }
    return any && !isTrimScalar(first) && !isTrimScalar(last);
}

std::optional<std::vector<uint8_t>> decodeBase32Lower(std::string_view input) {
    std::vector<uint8_t> output;
    output.reserve(input.size() * 5 / 8);
    uint32_t buffer = 0;
    int bits = 0;
    for (const char byte : input) {
        int value = -1;
        if (byte >= 'a' && byte <= 'z') value = byte - 'a';
        else if (byte >= '2' && byte <= '7') value = byte - '2' + 26;
        if (value < 0) return std::nullopt;
        buffer = (buffer << 5) | static_cast<uint32_t>(value);
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
        if (bits != 0) buffer &= (1U << bits) - 1U;
        else buffer = 0;
    }
    if (bits != 0 && buffer != 0) return std::nullopt;
    return output;
}

std::string encodeBase32Lower(std::span<const uint8_t> input) {
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    std::string output;
    output.reserve((input.size() * 8 + 4) / 5);
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t byte : input) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output.push_back(alphabet[(buffer >> bits) & 0x1f]);
        }
        if (bits != 0) buffer &= (1U << bits) - 1U;
        else buffer = 0;
    }
    if (bits != 0) output.push_back(alphabet[(buffer << (5 - bits)) & 0x1f]);
    return output;
}

bool validCid(std::string_view cid, std::string_view expected_sha) {
    if (cid.size() != 59 || cid.front() != 'b' || !isLowerHex(expected_sha, 64)) {
        return false;
    }
    auto decoded = decodeBase32Lower(cid.substr(1));
    if (!decoded.has_value() || decoded->size() != 36 || (*decoded)[0] != 0x01 ||
        (*decoded)[1] != 0x55 || (*decoded)[2] != 0x12 || (*decoded)[3] != 0x20 ||
        encodeBase32Lower(*decoded) != cid.substr(1)) {
        return false;
    }
    return hex(std::span<const uint8_t>(decoded->data() + 4, 32)) == expected_sha;
}

bool validCandidate(std::string_view candidate, std::string_view sha) {
    constexpr std::string_view prefix = "asset-review:";
    if (candidate.size() > 206 || !candidate.starts_with(prefix) ||
        candidate.size() <= prefix.size() + 1 + sha.size()) return false;
    const size_t separator = candidate.size() - sha.size() - 1;
    if (candidate[separator] != ':' || candidate.substr(separator + 1) != sha) {
        return false;
    }
    const std::string_view entity = candidate.substr(prefix.size(),
                                                      separator - prefix.size());
    if (entity.empty() || entity.size() > 128) return false;
    const size_t slash = entity.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= entity.size() ||
        entity.find('/', slash + 1) != std::string_view::npos) return false;
    for (size_t i = 0; i < entity.size(); ++i) {
        const char byte = entity[i];
        if (i == slash) continue;
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
              byte == '-')) return false;
    }
    const char after_slash = entity[slash + 1];
    return (after_slash >= 'a' && after_slash <= 'z') ||
           (after_slash >= '0' && after_slash <= '9');
}

double binary64Hypot4(const std::array<double, 4>& values) {
    double maximum = 0;
    for (const double value : values) maximum = std::max(maximum, std::abs(value));
    if (maximum == 0) return 0;

    // This is the frozen four-input IEEE-754 binary64 Math.hypot algorithm:
    // normalize by the largest magnitude and use compensated summation.  Keep
    // each intermediate as double so native validation agrees with the
    // browser implementation at the 1e-6 boundary.
    double sum = 0;
    double compensation = 0;
    for (const double value : values) {
        const double normalized = std::abs(value) / maximum;
        const double normalized_squared = normalized * normalized;
        const double summand = normalized_squared - compensation;
        const double preliminary = sum + summand;
        compensation = (preliminary - sum) - summand;
        sum = preliminary;
    }
    return std::sqrt(sum) * maximum;
}

bool validTransform(const ReviewedTransform& transform) {
    for (const double value : transform.translation) {
        if (!std::isfinite(value) || std::abs(value) > 1000000.0) return false;
    }
    for (const double value : transform.scale) {
        if (!std::isfinite(value) || value <= 0 || value > 1000000.0) return false;
    }
    for (const double value : transform.rotation) {
        if (!std::isfinite(value)) return false;
    }
    const double rotation_norm = binary64Hypot4(transform.rotation);
    if (std::abs(rotation_norm - 1.0) > 0.000001) return false;
    if (!(transform.up_axis == "X_UP" || transform.up_axis == "Y_UP" ||
          transform.up_axis == "Z_UP")) return false;
    double expected = 0;
    if (transform.source_units == "m") expected = 1;
    else if (transform.source_units == "cm") expected = 0.01;
    else if (transform.source_units == "mm") expected = 0.001;
    else if (transform.source_units == "km") expected = 1000;
    else return false;
    return std::isfinite(transform.meters_per_source_unit) &&
           transform.meters_per_source_unit == expected;
}

Value arrayValue(std::span<const double> values) {
    Value::Array array;
    array.reserve(values.size());
    for (const double value : values) array.emplace_back(value);
    return Value(std::move(array));
}

IdentityOutcome<std::string> canonicalize(Value::Members members) {
    auto result = jcs::serialize_jcs(Value(std::move(members)), jcs::Limits{});
    if (std::holds_alternative<jcs::JcsError>(result)) {
        return std::get<jcs::JcsError>(result) == jcs::JcsError::OutOfMemory
                   ? IdentityError::OutOfMemory
                   : IdentityError::InvalidRequest;
    }
    return std::get<std::string>(std::move(result));
}

CanonicalSignature signCanonical(IdentityRecord& record,
                                 bool approval,
                                 std::string canonical) {
    SecretBuffer digest(32);
    internal::sha256_secret(bytes(canonical),
                            std::span<uint8_t, 32>(digest.data(), 32));
    const SecretBuffer& private_key = approval ? record.material.approval_private
                                                : record.material.authentication_private;
    const auto signature = internal::sign_ed25519(
        std::span<const uint8_t, 32>(private_key.data(), 32), digest.span());
    const auto& descriptor = approval ? record.public_identity.keys[0]
                                      : record.public_identity.keys[2];
    CanonicalSignature result{
        1,
        descriptor.key_id,
        descriptor.identity_scheme,
        "ed25519",
        KeyEncoding::Raw,
        std::string(kSignatureProfile),
        std::move(canonical),
        {},
        signature,
    };
    std::copy_n(digest.data(), 32, result.signed_digest.data());
    return result;
}

const Value* member(const Value& object, std::string_view name) {
    if (object.kind() != Value::Kind::Object) return nullptr;
    for (const auto& candidate : object.members()) {
        if (candidate.first == name) return &candidate.second;
    }
    return nullptr;
}

SecretBuffer decodeBase64Url(std::string_view encoded, bool& valid) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    valid = false;
    if (encoded.find('=') != std::string_view::npos || encoded.size() % 4 == 1) {
        return SecretBuffer{};
    }
    SecretBuffer output;
    output.reserve(encoded.size() * 3 / 4 + 2);
    uint32_t buffer = 0;
    int bits = 0;
    for (const char byte : encoded) {
        const size_t position = alphabet.find(byte);
        if (position == std::string_view::npos) return SecretBuffer{};
        buffer = (buffer << 6) | static_cast<uint32_t>(position);
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
        if (bits != 0) buffer &= (1U << bits) - 1U;
        else buffer = 0;
    }
    if (bits != 0 && buffer != 0) return SecretBuffer{};
    valid = true;
    return output;
}

std::string encodeBase64Url(std::span<const uint8_t> input) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((input.size() * 4 + 2) / 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t byte : input) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output.push_back(alphabet[(buffer >> bits) & 0x3f]);
        }
        if (bits != 0) buffer &= (1U << bits) - 1U;
        else buffer = 0;
    }
    if (bits != 0) output.push_back(alphabet[(buffer << (6 - bits)) & 0x3f]);
    return output;
}

SecretBuffer encodeBase64UrlSecret(std::span<const uint8_t> input) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    SecretBuffer output;
    output.reserve((input.size() * 4 + 2) / 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t byte : input) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output.push_back(alphabet[(buffer >> bits) & 0x3f]);
        }
        if (bits != 0) buffer &= (1U << bits) - 1U;
        else buffer = 0;
    }
    if (bits != 0) output.push_back(alphabet[(buffer << (6 - bits)) & 0x3f]);
    return output;
}

enum class AadValidation : uint8_t { Valid, Invalid, OutOfMemory };

AadValidation validateAad(std::span<const uint8_t> aad,
                          std::string_view username) {
    if (aad.empty() || aad.size() > 4096) return AadValidation::Invalid;
    auto parsed = jcs::parse_exact_jcs(aad, jcs::Limits{4096, 8, 32, 2048});
    if (!std::holds_alternative<Value>(parsed)) {
        return std::get<jcs::JcsError>(parsed) == jcs::JcsError::OutOfMemory
                   ? AadValidation::OutOfMemory
                   : AadValidation::Invalid;
    }
    const Value& object = std::get<Value>(parsed);
    if (object.kind() != Value::Kind::Object || object.members().size() != 6) {
        return AadValidation::Invalid;
    }
    const Value* credential = member(object, "credentialIdBase64url");
    const Value* scheme = member(object, "identityScheme");
    const Value* version = member(object, "schemaVersion");
    const Value* profile = member(object, "seedProfile");
    const Value* storage = member(object, "storageProfile");
    const Value* username_hash = member(object, "usernameSha256");
    if (!credential || !scheme || !version || !profile || !storage ||
        !username_hash || credential->kind() != Value::Kind::String ||
        scheme->kind() != Value::Kind::String || version->kind() != Value::Kind::Number ||
        profile->kind() != Value::Kind::String || storage->kind() != Value::Kind::String ||
        username_hash->kind() != Value::Kind::String || version->number() != 2 ||
        scheme->string() != kIdentityScheme || profile->string() != kPasswordProfile ||
        storage->string() != kStorageProfile) {
        return AadValidation::Invalid;
    }
    bool decoded_ok = false;
    auto decoded = decodeBase64Url(credential->string(), decoded_ok);
    if (!decoded_ok || decoded.empty() || decoded.size() > 1024 ||
        encodeBase64Url(decoded.span()) != credential->string()) {
        return AadValidation::Invalid;
    }
    const auto hash = internal::sha256_public(bytes(username));
    return username_hash->string() == hex(hash) ? AadValidation::Valid
                                                 : AadValidation::Invalid;
}

SecretBuffer rememberInfo(std::string_view username) {
    SecretBuffer result;
    result.reserve(kRememberInfo.size() + 1 + username.size());
    for (const uint8_t byte : bytes(kRememberInfo)) result.push_back(byte);
    result.push_back(0);
    for (const uint8_t byte : bytes(username)) result.push_back(byte);
    return result;
}

SecretBuffer rememberPlaintext(std::span<const uint8_t> password,
                               std::string_view username) {
    const SecretBuffer encoded = encodeBase64UrlSecret(password);
    const std::string prefix =
        "{\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\","
        "\"passwordBase64url\":\"";
    const std::string middle =
        "\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"";
    constexpr std::string_view suffix = "\"}";
    SecretBuffer output;
    output.reserve(prefix.size() + encoded.size() + middle.size() +
                   username.size() + suffix.size());
    for (const uint8_t byte : bytes(prefix)) output.push_back(byte);
    for (const uint8_t byte : encoded.span()) output.push_back(byte);
    for (const uint8_t byte : bytes(middle)) output.push_back(byte);
    for (const uint8_t byte : bytes(username)) output.push_back(byte);
    for (const uint8_t byte : bytes(suffix)) output.push_back(byte);
    return output;
}

IdentityOutcome<SecretBuffer> passwordFromPlaintext(
    std::span<const uint8_t> plaintext,
    std::string_view expected_username) {
    constexpr std::string_view prefix =
        "{\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\","
        "\"passwordBase64url\":\"";
    constexpr std::string_view middle =
        "\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"";
    constexpr std::string_view suffix = "\"}";
    const std::string_view input(reinterpret_cast<const char*>(plaintext.data()),
                                 plaintext.size());
    if (!input.starts_with(prefix) || !input.ends_with(suffix)) {
        return IdentityError::InvalidRequest;
    }
    const size_t middle_position = input.find(middle, prefix.size());
    if (middle_position == std::string_view::npos) return IdentityError::InvalidRequest;
    const std::string_view encoded = input.substr(prefix.size(),
                                                   middle_position - prefix.size());
    const size_t username_begin = middle_position + middle.size();
    const std::string_view username = input.substr(
        username_begin, input.size() - suffix.size() - username_begin);
    if (username != expected_username) return IdentityError::InvalidRequest;
    bool decoded_ok = false;
    auto password = decodeBase64Url(encoded, decoded_ok);
    const auto canonical_encoded = encodeBase64UrlSecret(password.span());
    if (!decoded_ok || password.empty() || password.size() > 256 ||
        canonical_encoded.size() != encoded.size() ||
        !std::equal(canonical_encoded.span().begin(), canonical_encoded.span().end(),
                    reinterpret_cast<const uint8_t*>(encoded.data()))) {
        return IdentityError::InvalidRequest;
    }
    return std::move(password);
}

} // namespace

namespace {

template <typename MaterialDeriver>
IdentityOutcome<IdentityHandle> deriveLegacyPasswordIdentityImpl(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    uint32_t account_index,
    MaterialDeriver&& derive_material) {
#if HD_WALLET_FIPS_MODE
    (void)exact_legacy_username_utf8;
    (void)exact_legacy_password_utf8;
    (void)account_index;
    (void)derive_material;
    return IdentityError::FipsNotAllowed;
#else
    if (account_index > 1) return IdentityError::InvalidAccountIndex;
    if (exact_legacy_username_utf8.size() > 4096 ||
        !strictUtf8(exact_legacy_username_utf8)) {
        return IdentityError::InvalidUsername;
    }
    if (exact_legacy_password_utf8.size() > 4096 ||
        !strictUtf8(exact_legacy_password_utf8)) {
        return IdentityError::InvalidPassword;
    }
    auto derived = derive_legacy_password_seed(exact_legacy_username_utf8,
                                               exact_legacy_password_utf8);
    if (std::holds_alternative<PasswordError>(derived)) {
        return mapPasswordError(std::get<PasswordError>(derived));
    }
    return safeOutcome<IdentityHandle>([&]() -> IdentityOutcome<IdentityHandle> {
        auto seed = std::get<PasswordSeed>(std::move(derived));
        std::string username = seed.canonical_username;
        return insertRawSeed(
            SecretBuffer(std::move(seed.bytes)), IdentityKind::LegacyPassword,
            account_index, std::move(username),
            std::forward<MaterialDeriver>(derive_material));
    });
#endif
}

} // namespace

IdentityOutcome<IdentityHandle> derive_password_identity(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8,
    uint32_t account_index) {
#if HD_WALLET_FIPS_MODE
    (void)username_utf8;
    (void)exact_password_utf8;
    (void)account_index;
    return IdentityError::FipsNotAllowed;
#else
    if (account_index > 1) return IdentityError::InvalidAccountIndex;
    auto checked_username = canonicalize_username(username_utf8);
    if (std::holds_alternative<PasswordError>(checked_username)) {
        return IdentityError::InvalidUsername;
    }
    auto derived = derive_password_seed(username_utf8, exact_password_utf8);
    if (std::holds_alternative<PasswordError>(derived)) {
        return mapPasswordError(std::get<PasswordError>(derived));
    }
    return safeOutcome<IdentityHandle>([&]() -> IdentityOutcome<IdentityHandle> {
        auto seed = std::get<PasswordSeed>(std::move(derived));
        std::string username = seed.canonical_username;
        return insertRawSeed(
            SecretBuffer(std::move(seed.bytes)), IdentityKind::PasswordV2,
            account_index, std::move(username), internal::derive_identity_material);
    });
#endif
}

IdentityOutcome<IdentityHandle> derive_legacy_password_identity(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    uint32_t account_index) {
    return deriveLegacyPasswordIdentityImpl(
        exact_legacy_username_utf8, exact_legacy_password_utf8, account_index,
        internal::derive_identity_material);
}

IdentityOutcome<IdentityHandle> import_legacy_mnemonic_identity(
    std::span<const uint8_t> mnemonic_utf8,
    uint32_t account_index) {
#if HD_WALLET_FIPS_MODE
    (void)mnemonic_utf8;
    (void)account_index;
    return IdentityError::FipsNotAllowed;
#else
    if (account_index > 1) return IdentityError::InvalidAccountIndex;
    auto seed = internal::derive_legacy_mnemonic_seed(mnemonic_utf8);
    if (std::holds_alternative<IdentityError>(seed)) {
        return std::get<IdentityError>(seed);
    }
    return safeOutcome<IdentityHandle>([&]() -> IdentityOutcome<IdentityHandle> {
        return insertRawSeed(
            std::get<SecretBuffer>(std::move(seed)), IdentityKind::LegacyMnemonic,
            account_index, {}, internal::derive_identity_material);
    });
#endif
}

IdentityOutcome<PublicIdentity> describe_identity(IdentityHandle handle) {
    return safeOutcome<PublicIdentity>([&]() -> IdentityOutcome<PublicIdentity> {
        std::lock_guard lock(g_slots_mutex);
        const auto* record = lookupLocked(handle);
        if (!record) return IdentityError::StaleHandle;
        return record->public_identity;
    });
}

namespace {

template <typename Signer>
IdentityOutcome<RawSignature> signSdnLoginV1Impl(
    IdentityHandle handle,
    std::span<const uint8_t, 32> challenge,
    Signer&& signer) {
#if HD_WALLET_FIPS_MODE
    (void)handle;
    (void)challenge;
    (void)signer;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<RawSignature>([&]() -> IdentityOutcome<RawSignature> {
        std::lock_guard lock(g_slots_mutex);
        auto* record = lookupLocked(handle);
        if (!record) return IdentityError::StaleHandle;
        if (record->material.kind == IdentityKind::PasswordV2) {
            return IdentityError::OperationNotAllowed;
        }
        const auto& descriptor = record->public_identity.keys.front();
        return RawSignature{
            1,
            descriptor.key_id,
            descriptor.identity_scheme,
            "ed25519",
            KeyEncoding::Raw,
            std::string(kRawSignatureProfile),
            signer(std::span<const uint8_t, 32>(
                       record->material.authentication_private.data(), 32),
                   challenge),
        };
    });
#endif
}

} // namespace

IdentityOutcome<RawSignature> sign_sdn_login_v1(
    IdentityHandle handle,
    std::span<const uint8_t, 32> challenge) {
    return signSdnLoginV1Impl(handle, challenge, internal::sign_ed25519);
}

IdentityOutcome<CanonicalSignature> sign_sdn_login_v2(
    IdentityHandle handle,
    const SdnLoginV2Fields& request,
    RegistryRowId registry_row) {
#if HD_WALLET_FIPS_MODE
    (void)handle;
    (void)request;
    (void)registry_row;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<CanonicalSignature>([&]() -> IdentityOutcome<CanonicalSignature> {
        std::lock_guard lock(g_slots_mutex);
        auto* record = lookupLocked(handle);
        if (!record) return IdentityError::StaleHandle;
        if (record->material.kind != IdentityKind::PasswordV2) {
            return IdentityError::OperationNotAllowed;
        }
        const RegistryRow* row = registryRow(registry_row);
        if (row == nullptr || row->operation != RegisteredOperation::SdnLoginV2 ||
            request.audience != row->audience) {
            return IdentityError::OperationNotAllowed;
        }
        if (request.protocol_version != 2 || !isLowerHex(request.nonce, 64) ||
            !validLifetime(request.issued_at, request.expires_at,
                           row->maximum_lifetime_seconds) ||
            !validString(request.issued_at) || !validString(request.expires_at)) {
            return IdentityError::InvalidRequest;
        }
        const auto challenge_hash = internal::sha256_public(request.challenge);
        const auto& auth = record->public_identity.keys[2];
        Value::Members envelope{
            {"audience", std::string(row->audience)},
            {"challengeSha256", hex(challenge_hash)},
            {"clientId", std::string(row->client_id)},
            {"expiresAt", request.expires_at},
            {"identityScheme", std::string(kIdentityScheme)},
            {"issuedAt", request.issued_at},
            {"keyId", auth.key_id},
            {"kind", std::string("sdn-login")},
            {"nonce", request.nonce},
            {"protocolVersion", 2.0},
            {"requestOrigin", std::string(row->request_origin)},
            {"signatureProfile", std::string(kSignatureProfile)},
        };
        auto canonical = canonicalize(std::move(envelope));
        if (std::holds_alternative<IdentityError>(canonical)) {
            return std::get<IdentityError>(canonical);
        }
        return signCanonical(*record, false,
                             std::get<std::string>(std::move(canonical)));
    });
#endif
}

IdentityOutcome<CanonicalSignature> sign_asset_review_authority_activation(
    IdentityHandle handle,
    const AuthorityActivationFields& request,
    RegistryRowId registry_row) {
#if HD_WALLET_FIPS_MODE
    (void)handle;
    (void)request;
    (void)registry_row;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<CanonicalSignature>([&]() -> IdentityOutcome<CanonicalSignature> {
        std::lock_guard lock(g_slots_mutex);
        auto* record = lookupLocked(handle);
        if (!record) return IdentityError::StaleHandle;
        if (record->material.kind != IdentityKind::PasswordV2) {
            return IdentityError::OperationNotAllowed;
        }
        const RegistryRow* row = registryRow(registry_row);
        if (row == nullptr ||
            row->operation != RegisteredOperation::AssetReviewAuthorityActivation ||
            request.audience != row->audience ||
            request.request_origin != row->request_origin ||
            request.client_id != row->client_id ||
            request.service_instance != row->service_instance) {
            return IdentityError::OperationNotAllowed;
        }
        const auto& approval = record->public_identity.keys[0];
        if (request.protocol_version != 1 ||
            request.purpose != "asset-review-authority-activation" ||
            !isLowerHex(request.nonce, 64) ||
            !validLifetime(request.issued_at, request.expires_at,
                           row->maximum_lifetime_seconds) ||
            request.public_key_hex != hex(record->material.approval_public) ||
            request.key_id != approval.key_id ||
            request.identity_scheme != kIdentityScheme ||
            request.signature_profile != kSignatureProfile) {
            return IdentityError::InvalidRequest;
        }
        Value::Members envelope{
            {"audience", std::string(row->audience)},
            {"clientId", std::string(row->client_id)},
            {"expiresAt", request.expires_at},
            {"identityScheme", std::string(kIdentityScheme)},
            {"issuedAt", request.issued_at},
            {"keyId", approval.key_id},
            {"kind", std::string("asset-review-authority-activation")},
            {"nonce", request.nonce},
            {"protocolVersion", 1.0},
            {"publicKeyHex", hex(record->material.approval_public)},
            {"purpose", std::string("asset-review-authority-activation")},
            {"requestOrigin", std::string(row->request_origin)},
            {"serviceInstance", std::string(row->service_instance)},
            {"signatureProfile", std::string(kSignatureProfile)},
        };
        auto canonical = canonicalize(std::move(envelope));
        if (std::holds_alternative<IdentityError>(canonical)) {
            return std::get<IdentityError>(canonical);
        }
        return signCanonical(*record, true,
                             std::get<std::string>(std::move(canonical)));
    });
#endif
}

IdentityOutcome<CanonicalSignature> sign_asset_review_decision(
    IdentityHandle handle,
    const AssetReviewDecisionFields& request,
    RegistryRowId registry_row) {
#if HD_WALLET_FIPS_MODE
    (void)handle;
    (void)request;
    (void)registry_row;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<CanonicalSignature>([&]() -> IdentityOutcome<CanonicalSignature> {
        std::lock_guard lock(g_slots_mutex);
        auto* record = lookupLocked(handle);
        if (!record) return IdentityError::StaleHandle;
        if (record->material.kind != IdentityKind::PasswordV2) {
            return IdentityError::OperationNotAllowed;
        }
        const RegistryRow* row = registryRow(registry_row);
        if (row == nullptr ||
            row->operation != RegisteredOperation::AssetReviewDecision ||
            request.audience != row->audience ||
            request.request_origin != row->request_origin ||
            request.client_id != row->client_id) {
            return IdentityError::OperationNotAllowed;
        }
        size_t string_bytes = 0;
        const auto add_string_bytes = [&string_bytes](size_t count) {
            if (count > 16384 - string_bytes) return false;
            string_bytes += count;
            return true;
        };
        bool strings_fit = add_string_bytes(request.audience.size()) &&
                           add_string_bytes(request.request_origin.size()) &&
                           add_string_bytes(request.client_id.size()) &&
                           add_string_bytes(request.challenge_id.size()) &&
                           add_string_bytes(request.nonce.size()) &&
                           add_string_bytes(request.issued_at.size()) &&
                           add_string_bytes(request.expires_at.size()) &&
                           add_string_bytes(request.candidate_key.size()) &&
                           add_string_bytes(request.model_cid.size()) &&
                           add_string_bytes(request.model_sha256.size()) &&
                           add_string_bytes(request.metadata_sha256.size());
        if (request.previous_decision_head) {
            strings_fit = strings_fit &&
                          add_string_bytes(request.previous_decision_head->size());
        }
        if (request.note) {
            strings_fit = strings_fit && add_string_bytes(request.note->size());
        }
        if (request.reason) {
            strings_fit = strings_fit && add_string_bytes(request.reason->size());
        }
        if (request.reviewed_transform) {
            strings_fit = strings_fit &&
                          add_string_bytes(request.reviewed_transform->up_axis.size()) &&
                          add_string_bytes(
                              request.reviewed_transform->source_units.size());
        }
        if (!strings_fit || request.protocol_version != 1 ||
            !isLowerHex(request.challenge_id, 64) || !isLowerHex(request.nonce, 64) ||
            !validLifetime(request.issued_at, request.expires_at,
                           row->maximum_lifetime_seconds) ||
            !isLowerHex(request.model_sha256, 64) ||
            !isLowerHex(request.metadata_sha256, 64) ||
            (request.previous_decision_head &&
             !isLowerHex(*request.previous_decision_head, 64)) ||
            request.model_bytes == 0 || request.model_bytes > 9007199254740991ULL ||
            !validCid(request.model_cid, request.model_sha256) ||
            !validCandidate(request.candidate_key, request.model_sha256)) {
            return IdentityError::InvalidRequest;
        }
        const bool approve = request.decision == ReviewDecision::Approve;
        const bool disapprove = request.decision == ReviewDecision::Disapprove;
        if ((!approve && !disapprove) ||
            (approve && (!request.reviewed_transform || request.reason ||
                         !trimmedText(request.note, true) ||
                         !validTransform(*request.reviewed_transform))) ||
            (disapprove && (request.reviewed_transform || request.note ||
                            !trimmedText(request.reason, false)))) {
            return IdentityError::InvalidRequest;
        }
        const auto& approval = record->public_identity.keys[0];
        Value::Members envelope{
            {"audience", std::string(row->audience)},
            {"candidateKey", request.candidate_key},
            {"challengeId", request.challenge_id},
            {"clientId", std::string(row->client_id)},
            {"decision", std::string(approve ? "approve" : "disapprove")},
            {"expiresAt", request.expires_at},
            {"identityScheme", std::string(kIdentityScheme)},
            {"issuedAt", request.issued_at},
            {"keyId", approval.key_id},
            {"kind", std::string("asset-review-attestation")},
            {"metadataSha256", request.metadata_sha256},
            {"modelBytes", static_cast<double>(request.model_bytes)},
            {"modelCid", request.model_cid},
            {"modelSha256", request.model_sha256},
            {"nonce", request.nonce},
            {"previousDecisionHead", request.previous_decision_head
                                         ? Value(*request.previous_decision_head)
                                         : Value(nullptr)},
            {"protocolVersion", 1.0},
            {"purpose", std::string("asset-review-approval")},
            {"requestOrigin", std::string(row->request_origin)},
            {"signatureProfile", std::string(kSignatureProfile)},
        };
        if (approve) {
            const auto& transform = *request.reviewed_transform;
            if (request.note) envelope.emplace_back("note", *request.note);
            else envelope.emplace_back("note", Value(nullptr));
            Value::Members transform_object{
                {"metersPerSourceUnit", transform.meters_per_source_unit},
                {"rotation", arrayValue(transform.rotation)},
                {"scale", arrayValue(transform.scale)},
                {"sourceUnits", transform.source_units},
                {"translation", arrayValue(transform.translation)},
                {"upAxis", transform.up_axis},
            };
            envelope.emplace_back("reviewedTransform", Value(std::move(transform_object)));
        } else {
            envelope.emplace_back("reason", *request.reason);
        }
        auto canonical = canonicalize(std::move(envelope));
        if (std::holds_alternative<IdentityError>(canonical)) {
            return std::get<IdentityError>(canonical);
        }
        return signCanonical(*record, true,
                             std::get<std::string>(std::move(canonical)));
    });
#endif
}

namespace {

IdentityOutcome<PasswordSeed> mapRememberPasswordOutcome(
    internal::DetailedPasswordOutcome&& outcome) {
    if (std::holds_alternative<PasswordSeed>(outcome)) {
        return std::get<PasswordSeed>(std::move(outcome));
    }
    const auto failure =
        std::get<internal::PasswordDerivationFailure>(outcome);
    switch (failure.kind) {
        case internal::PasswordDerivationFailureKind::OutOfMemory:
            return IdentityError::OutOfMemory;
        case internal::PasswordDerivationFailureKind::CryptoFailure:
            return IdentityError::CryptoFailure;
        case internal::PasswordDerivationFailureKind::Policy:
            return IdentityError::AuthenticationFailed;
    }
    return IdentityError::CryptoFailure;
}

template <typename PasswordDeriver, typename Hkdf, typename AeadSeal>
IdentityOutcome<std::vector<uint8_t>> rememberWalletSealImpl(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    PasswordDeriver&& derive_password,
    Hkdf&& hkdf,
    AeadSeal&& aead_seal) {
#if HD_WALLET_FIPS_MODE
    (void)handle;
    (void)exact_password_utf8;
    (void)prf_output;
    (void)hkdf_salt;
    (void)nonce;
    (void)canonical_aad_utf8;
    (void)derive_password;
    (void)hkdf;
    (void)aead_seal;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<std::vector<uint8_t>>(
        [&]() -> IdentityOutcome<std::vector<uint8_t>> {
            std::lock_guard lock(g_slots_mutex);
            auto* record = lookupLocked(handle);
            if (!record) return IdentityError::StaleHandle;
            if (record->material.kind != IdentityKind::PasswordV2 ||
                record->material.account_index != 0) {
                return IdentityError::OperationNotAllowed;
            }
            const auto aad_validation =
                validateAad(canonical_aad_utf8, record->canonical_username);
            if (aad_validation != AadValidation::Valid) {
                return aad_validation == AadValidation::OutOfMemory
                           ? IdentityError::OutOfMemory
                           : IdentityError::InvalidRequest;
            }
            auto verified = mapRememberPasswordOutcome(derive_password(
                bytes(record->canonical_username), exact_password_utf8));
            if (std::holds_alternative<IdentityError>(verified)) {
                return std::get<IdentityError>(verified);
            }
            auto verified_seed = std::get<PasswordSeed>(std::move(verified));
            if (!internal::constant_time_equal(verified_seed.bytes,
                                               record->material.seed.span())) {
                return IdentityError::AuthenticationFailed;
            }
            auto info = rememberInfo(record->canonical_username);
            auto key = hkdf(prf_output, hkdf_salt, info.span(), 32);
            auto plaintext = rememberPlaintext(exact_password_utf8,
                                               record->canonical_username);
            return aead_seal(
                std::span<const uint8_t, 32>(key.data(), 32), nonce,
                plaintext.span(), canonical_aad_utf8);
        });
#endif
}

template <typename PasswordDeriver,
          typename Hkdf,
          typename AeadOpen,
          typename MaterialDeriver>
IdentityOutcome<ImportedIdentity> rememberWalletOpenImpl(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8,
    PasswordDeriver&& derive_password,
    Hkdf&& hkdf,
    AeadOpen&& aead_open,
    MaterialDeriver&& derive_material) {
#if HD_WALLET_FIPS_MODE
    (void)ciphertext_and_tag;
    (void)prf_output;
    (void)hkdf_salt;
    (void)nonce;
    (void)canonical_username_utf8;
    (void)canonical_aad_utf8;
    (void)derive_password;
    (void)hkdf;
    (void)aead_open;
    (void)derive_material;
    return IdentityError::FipsNotAllowed;
#else
    return safeOutcome<ImportedIdentity>([&]() -> IdentityOutcome<ImportedIdentity> {
        if (ciphertext_and_tag.size() < 16 || ciphertext_and_tag.size() > 1024) {
            return IdentityError::InvalidRequest;
        }
        auto canonical = canonicalize_username(canonical_username_utf8);
        if (!std::holds_alternative<std::string>(canonical)) {
            return std::get<PasswordError>(canonical) == PasswordError::KdfFailure
                       ? IdentityError::OutOfMemory
                       : IdentityError::InvalidRequest;
        }
        std::string username = std::get<std::string>(std::move(canonical));
        const auto aad_validation = validateAad(canonical_aad_utf8, username);
        if (bytes(username).size() != canonical_username_utf8.size() ||
            !std::equal(canonical_username_utf8.begin(), canonical_username_utf8.end(),
                        bytes(username).begin())) {
            return IdentityError::InvalidRequest;
        }
        if (aad_validation != AadValidation::Valid) {
            return aad_validation == AadValidation::OutOfMemory
                       ? IdentityError::OutOfMemory
                       : IdentityError::InvalidRequest;
        }
        auto info = rememberInfo(username);
        auto key = hkdf(prf_output, hkdf_salt, info.span(), 32);

        // Keep authenticated plaintext and decoded password in a nested scope.
        // Both full-capacity-wiped owners die before any public DTO is copied or
        // any handle-table slot can become live.
        IdentityOutcome<PasswordSeed> recovered = [&]() -> IdentityOutcome<PasswordSeed> {
            auto opened = aead_open(
                std::span<const uint8_t, 32>(key.data(), 32), nonce,
                ciphertext_and_tag, canonical_aad_utf8);
            if (std::holds_alternative<IdentityError>(opened)) {
                return std::get<IdentityError>(opened);
            }
            auto plaintext = std::get<SecretBuffer>(std::move(opened));
            auto password = passwordFromPlaintext(plaintext.span(), username);
            if (std::holds_alternative<IdentityError>(password)) {
                return std::get<IdentityError>(password);
            }
            auto password_bytes = std::get<SecretBuffer>(std::move(password));
            return mapRememberPasswordOutcome(
                derive_password(bytes(username), password_bytes.span()));
        }();
        if (std::holds_alternative<IdentityError>(recovered)) {
            return std::get<IdentityError>(recovered);
        }
        auto seed = std::get<PasswordSeed>(std::move(recovered));
        return insertRawSeedImported(
            SecretBuffer(std::move(seed.bytes)), IdentityKind::PasswordV2, 0,
            std::move(username), std::forward<MaterialDeriver>(derive_material));
    });
#endif
}

} // namespace

IdentityOutcome<std::vector<uint8_t>> remember_wallet_seal(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8) {
    return rememberWalletSealImpl(
        handle, exact_password_utf8, prf_output, hkdf_salt, nonce,
        canonical_aad_utf8, internal::derive_password_seed_detailed,
        internal::hkdf_sha256, internal::aes256_gcm_seal);
}

IdentityOutcome<ImportedIdentity> remember_wallet_open(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8) {
    return rememberWalletOpenImpl(
        ciphertext_and_tag, prf_output, hkdf_salt, nonce,
        canonical_username_utf8, canonical_aad_utf8,
        internal::derive_password_seed_detailed, internal::hkdf_sha256,
        internal::aes256_gcm_open, internal::derive_identity_material);
}

void destroy_identity(IdentityHandle handle) noexcept {
    try {
        std::lock_guard lock(g_slots_mutex);
        const uint32_t one_based_slot = static_cast<uint32_t>(handle);
        const uint32_t generation = static_cast<uint32_t>(handle >> 32);
        if (generation == 0 || one_based_slot == 0 ||
            one_based_slot > g_slots.size()) return;
        auto& slot = g_slots[one_based_slot - 1];
        if (slot.retired || slot.generation != generation ||
            !slot.record.has_value()) return;
        slot.record.reset();
        if (slot.generation == std::numeric_limits<uint32_t>::max()) {
            slot.retired = true;
        } else {
            ++slot.generation;
            if (slot.generation == 0) slot.retired = true;
        }
    } catch (...) {
        // Idempotent destruction is deliberately noexcept and fail-closed.
    }
}

#if defined(HD_WALLET_SDN_IDENTITY_TESTING) && HD_WALLET_SDN_IDENTITY_TESTING
namespace internal {

bool testing_set_empty_slot_generation(size_t zero_based_slot,
                                       uint32_t generation) noexcept {
    try {
        std::lock_guard lock(g_slots_mutex);
        if (zero_based_slot >= g_slots.size() || generation == 0) return false;
        auto& slot = g_slots[zero_based_slot];
        if (slot.retired || slot.record.has_value()) return false;
        slot.generation = generation;
        return true;
    } catch (...) {
        return false;
    }
}

size_t testing_retired_slot_count() noexcept {
    try {
        std::lock_guard lock(g_slots_mutex);
        return static_cast<size_t>(std::count_if(
            g_slots.begin(), g_slots.end(), [](const Slot& slot) {
                return slot.retired;
            }));
    } catch (...) {
        return 0;
    }
}

IdentityOutcome<IdentityHandle> testing_derive_legacy_password_identity(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    uint32_t account_index,
    TestingDerivationBackend backend) {
    const auto derive_material = [backend](SecretBuffer&& seed,
                                           IdentityKind kind,
                                           uint32_t account) {
        return testing_derive_identity_material(std::move(seed), kind, account,
                                                backend);
    };
    return deriveLegacyPasswordIdentityImpl(
        exact_legacy_username_utf8, exact_legacy_password_utf8, account_index,
        derive_material);
}

IdentityOutcome<RawSignature> testing_sign_sdn_login_v1(
    IdentityHandle handle,
    std::span<const uint8_t, 32> challenge,
    TestingSigningBackend backend) {
    const auto signer = [backend](std::span<const uint8_t, 32> seed,
                                  std::span<const uint8_t> message) {
        return testing_sign_ed25519(seed, message, backend);
    };
    return signSdnLoginV1Impl(handle, challenge, signer);
}

IdentityOutcome<std::vector<uint8_t>> testing_remember_wallet_seal_with_hkdf(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingHkdfBackend backend) {
    const auto hkdf = [backend](std::span<const uint8_t> ikm,
                                std::span<const uint8_t> salt,
                                std::span<const uint8_t> info,
                                size_t output_size) {
        return testing_hkdf_sha256_with_backend(ikm, salt, info, output_size,
                                                backend);
    };
    return rememberWalletSealImpl(
        handle, exact_password_utf8, prf_output, hkdf_salt, nonce,
        canonical_aad_utf8, derive_password_seed_detailed, hkdf,
        aes256_gcm_seal);
}

IdentityOutcome<std::vector<uint8_t>>
testing_remember_wallet_seal_with_password_kdf(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingPasswordKdfBackend backend) {
    const auto derive_password = [backend](std::span<const uint8_t> username,
                                           std::span<const uint8_t> password) {
        return testing_derive_password_seed_detailed(username, password,
                                                     backend);
    };
    return rememberWalletSealImpl(
        handle, exact_password_utf8, prf_output, hkdf_salt, nonce,
        canonical_aad_utf8, derive_password, hkdf_sha256, aes256_gcm_seal);
}

IdentityOutcome<std::vector<uint8_t>> testing_remember_wallet_seal_with_aead(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingAeadSealBackend backend) {
    const auto aead_seal = [backend](std::span<const uint8_t, 32> key,
                                     std::span<const uint8_t, 12> iv,
                                     std::span<const uint8_t> plaintext,
                                     std::span<const uint8_t> aad) {
        return testing_aes256_gcm_seal_with_backend(
            key, iv, plaintext, aad, backend);
    };
    return rememberWalletSealImpl(
        handle, exact_password_utf8, prf_output, hkdf_salt, nonce,
        canonical_aad_utf8, derive_password_seed_detailed, hkdf_sha256,
        aead_seal);
}

IdentityOutcome<ImportedIdentity> testing_remember_wallet_open_with_aead(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingAeadOpenBackend backend) {
    const auto aead_open = [backend](std::span<const uint8_t, 32> key,
                                     std::span<const uint8_t, 12> iv,
                                     std::span<const uint8_t> ciphertext,
                                     std::span<const uint8_t> aad) {
        return testing_aes256_gcm_open_with_backend(
            key, iv, ciphertext, aad, backend);
    };
    return rememberWalletOpenImpl(
        ciphertext_and_tag, prf_output, hkdf_salt, nonce,
        canonical_username_utf8, canonical_aad_utf8,
        derive_password_seed_detailed, hkdf_sha256, aead_open,
        derive_identity_material);
}

IdentityOutcome<ImportedIdentity>
testing_remember_wallet_open_with_password_kdf(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingPasswordKdfBackend backend) {
    const auto derive_password = [backend](std::span<const uint8_t> username,
                                           std::span<const uint8_t> password) {
        return testing_derive_password_seed_detailed(username, password,
                                                     backend);
    };
    return rememberWalletOpenImpl(
        ciphertext_and_tag, prf_output, hkdf_salt, nonce,
        canonical_username_utf8, canonical_aad_utf8, derive_password,
        hkdf_sha256, aes256_gcm_open, derive_identity_material);
}

size_t testing_secret_base64url_lifecycle(
    std::span<const uint8_t> secret_input) {
    const auto encoded = encodeBase64UrlSecret(secret_input);
    return encoded.size();
}

} // namespace internal
#endif

} // namespace hd_wallet::sdn
