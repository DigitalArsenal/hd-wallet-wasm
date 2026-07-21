#include "test_framework.h"

#include "hd_wallet/password_profile.h"
#include "hd_wallet/sdn_identity.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#ifndef TEST_VECTORS_PATH
#define TEST_VECTORS_PATH "."
#endif

namespace {

using hd_wallet::sdn::PasswordSeed;

struct Json {
    enum class Kind { Null, Boolean, Number, String, Array, Object } kind{Kind::Null};
    bool boolean{};
    std::string text;
    std::vector<Json> array;
    std::map<std::string, Json> object;

    const Json& at(const std::string& key) const {
        auto it = object.find(key);
        if (kind != Kind::Object || it == object.end()) {
            throw std::runtime_error("missing JSON key: " + key);
        }
        return it->second;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& source) : source_(source) {}

    Json parse() {
        Json value = parseValue();
        whitespace();
        if (position_ != source_.size()) fail("trailing JSON data");
        return value;
    }

private:
    Json parseValue() {
        whitespace();
        if (position_ >= source_.size()) fail("unexpected end of JSON");
        switch (source_[position_]) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': { Json v; v.kind = Json::Kind::String; v.text = parseString(); return v; }
            case 't': return parseLiteral("true", Json::Kind::Boolean, true);
            case 'f': return parseLiteral("false", Json::Kind::Boolean, false);
            case 'n': return parseLiteral("null", Json::Kind::Null, false);
            default: return parseNumber();
        }
    }

    Json parseObject() {
        Json result; result.kind = Json::Kind::Object; ++position_; whitespace();
        if (consume('}')) return result;
        while (true) {
            whitespace();
            if (position_ >= source_.size() || source_[position_] != '"') fail("object key");
            std::string key = parseString();
            whitespace(); expect(':');
            if (!result.object.emplace(std::move(key), parseValue()).second) fail("duplicate key");
            whitespace();
            if (consume('}')) return result;
            expect(',');
        }
    }

    Json parseArray() {
        Json result; result.kind = Json::Kind::Array; ++position_; whitespace();
        if (consume(']')) return result;
        while (true) {
            result.array.push_back(parseValue());
            whitespace();
            if (consume(']')) return result;
            expect(',');
        }
    }

    Json parseNumber() {
        Json result; result.kind = Json::Kind::Number;
        size_t start = position_;
        if (consume('-')) {}
        if (position_ >= source_.size() || !std::isdigit(static_cast<unsigned char>(source_[position_]))) fail("number");
        while (position_ < source_.size() && std::isdigit(static_cast<unsigned char>(source_[position_]))) ++position_;
        result.text = source_.substr(start, position_ - start);
        return result;
    }

    Json parseLiteral(const char* literal, Json::Kind kind, bool boolean) {
        const size_t length = std::char_traits<char>::length(literal);
        if (source_.compare(position_, length, literal) != 0) fail("literal");
        position_ += length;
        Json result; result.kind = kind; result.boolean = boolean; return result;
    }

    std::string parseString() {
        expect('"');
        std::string result;
        while (position_ < source_.size()) {
            unsigned char ch = static_cast<unsigned char>(source_[position_++]);
            if (ch == '"') return result;
            if (ch < 0x20) fail("control in string");
            if (ch != '\\') { result.push_back(static_cast<char>(ch)); continue; }
            if (position_ >= source_.size()) fail("escape");
            const char escaped = source_[position_++];
            switch (escaped) {
                case '"': case '\\': case '/': result.push_back(escaped); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                default: fail("unsupported JSON escape");
            }
        }
        fail("unterminated string");
    }

    void whitespace() {
        while (position_ < source_.size() &&
               (source_[position_] == ' ' || source_[position_] == '\n' ||
                source_[position_] == '\r' || source_[position_] == '\t')) ++position_;
    }
    bool consume(char expected) {
        if (position_ < source_.size() && source_[position_] == expected) { ++position_; return true; }
        return false;
    }
    void expect(char expected) {
        if (!consume(expected)) fail(std::string("expected ") + expected);
    }
    [[noreturn]] void fail(const std::string& message) const {
        throw std::runtime_error("invalid fixture JSON at byte " + std::to_string(position_) + ": " + message);
    }

    const std::string& source_;
    size_t position_{};
};

std::string loadFixture(const std::string& name = "sdn-wallet-vectors.v1.json") {
    const std::string path = std::string(TEST_VECTORS_PATH) + "/" + name;
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("required fixture missing: " + path);
    std::ostringstream contents;
    contents << input.rdbuf();
    if (!input.good() && !input.eof()) throw std::runtime_error("failed reading fixture: " + path);
    return contents.str();
}

std::vector<uint8_t> hexBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("odd hex length");
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    auto nibble = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
        if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
        throw std::runtime_error("invalid lowercase hex");
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return result;
}

std::span<const uint8_t> byteSpan(const std::vector<uint8_t>& value) {
    return {value.data(), value.size()};
}

void assertSeed(const std::vector<uint8_t>& username,
                const std::vector<uint8_t>& password,
                const std::string& canonicalUsername,
                const std::string& expectedHex) {
    auto result = hd_wallet::sdn::derive_password_seed(byteSpan(username), byteSpan(password));
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    const auto& seed = std::get<PasswordSeed>(result);
    ASSERT_STR_EQ(canonicalUsername, seed.canonical_username);
    const auto expected = hexBytes(expectedHex);
    ASSERT_EQ(expected.size(), seed.bytes.size());
    ASSERT_BYTES_EQ(expected.data(), seed.bytes.data(), expected.size());
}

template <typename T>
T take(hd_wallet::sdn::IdentityOutcome<T>&& outcome) {
    ASSERT_TRUE(std::holds_alternative<T>(outcome));
    return std::move(std::get<T>(outcome));
}

std::vector<uint8_t> utf8Bytes(const std::string& value) {
    return {reinterpret_cast<const uint8_t*>(value.data()),
            reinterpret_cast<const uint8_t*>(value.data()) + value.size()};
}

const hd_wallet::sdn::PublicKeyDescriptor& descriptorFor(
    const hd_wallet::sdn::PublicIdentity& identity,
    hd_wallet::sdn::Purpose purpose) {
    auto it = std::find_if(identity.keys.begin(), identity.keys.end(),
                           [purpose](const auto& value) {
                               return value.purpose == purpose;
                           });
    if (it == identity.keys.end()) throw std::runtime_error("missing public descriptor");
    return *it;
}

uint32_t uint32Value(const Json& value) {
    if (value.kind != Json::Kind::Number) throw std::runtime_error("expected JSON integer");
    return static_cast<uint32_t>(std::stoul(value.text));
}

uint64_t uint64Value(const Json& value) {
    if (value.kind != Json::Kind::Number) throw std::runtime_error("expected JSON integer");
    return static_cast<uint64_t>(std::stoull(value.text));
}

std::array<uint8_t, 32> sequence(uint8_t first) {
    std::array<uint8_t, 32> result{};
    for (size_t i = 0; i < result.size(); ++i) result[i] = static_cast<uint8_t>(first + i);
    return result;
}

std::string hexArray(const std::array<uint8_t, 32>& value) {
    return test::bytesToHex(value);
}

std::string hexArray(const std::array<uint8_t, 64>& value) {
    return test::bytesToHex(value);
}

} // namespace

TEST_CASE(SdnVectors, PasswordFixtureSchemaAndAllFrozenSeeds) {
    const Json root = JsonParser(loadFixture()).parse();
    ASSERT_TRUE(root.kind == Json::Kind::Object);
    ASSERT_EQ(size_t{8}, root.object.size());
    ASSERT_TRUE(root.at("schemaVersion").kind == Json::Kind::Number);
    ASSERT_STR_EQ("1", root.at("schemaVersion").text);
    ASSERT_TRUE(root.at("purposeSeparatedMnemonicPrimitive").kind == Json::Kind::Object);
    ASSERT_TRUE(root.at("legacySource").kind == Json::Kind::Object);
    ASSERT_TRUE(root.at("leadingZeroFingerprint").kind == Json::Kind::Object);
    ASSERT_TRUE(root.at("operationMatrix").kind == Json::Kind::Array);

#if HD_WALLET_FIPS_MODE
    SKIP_TEST("scrypt profile is intentionally unavailable in FIPS mode");
#else

    const Json& newIdentity = root.at("newIdentity");
    ASSERT_TRUE(newIdentity.kind == Json::Kind::Object);
    ASSERT_EQ(size_t{5}, newIdentity.object.size());
    ASSERT_STR_EQ("sdn-bip32-slip10-purpose-v1", newIdentity.at("identityScheme").text);
    ASSERT_STR_EQ("password-scrypt-v2", newIdentity.at("seedProfile").text);
    ASSERT_STR_EQ("password-scrypt-v2-ascii", newIdentity.at("identitySource").text);
    ASSERT_TRUE(newIdentity.at("accounts").kind == Json::Kind::Array);
    const Json& passwordVectors = newIdentity.at("passwordVectors");
    ASSERT_TRUE(passwordVectors.kind == Json::Kind::Array);
    ASSERT_EQ(size_t{3}, passwordVectors.array.size());
    size_t assertedLocations = 0;
    for (const Json& vector : passwordVectors.array) {
        ASSERT_TRUE(vector.kind == Json::Kind::Object);
        ASSERT_EQ(size_t{7}, vector.object.size());
        ASSERT_TRUE(vector.at("name").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("rawUsername").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("rawUsernameUtf8Hex").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("canonicalUsername").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("password").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("passwordUtf8Hex").kind == Json::Kind::String);
        ASSERT_TRUE(vector.at("seedHex").kind == Json::Kind::String);
        const auto username = hexBytes(vector.at("rawUsernameUtf8Hex").text);
        const auto password = hexBytes(vector.at("passwordUtf8Hex").text);
        assertSeed(username, password, vector.at("canonicalUsername").text,
                   vector.at("seedHex").text);
        ++assertedLocations;
    }

    const auto reviewOwner = hexBytes("5265766965772d4f776e6572");
    const Json& validationCases = root.at("validationCases");
    ASSERT_TRUE(validationCases.kind == Json::Kind::Object);
    ASSERT_EQ(size_t{3}, validationCases.object.size());
    ASSERT_TRUE(validationCases.at("username").kind == Json::Kind::Array);
    ASSERT_TRUE(validationCases.at("identityImport").kind == Json::Kind::Array);
    const Json& passwordCases = validationCases.at("password");
    ASSERT_TRUE(passwordCases.kind == Json::Kind::Array);
    size_t acceptedLocations = 0;
    for (const Json& validation : passwordCases.array) {
        ASSERT_TRUE(validation.kind == Json::Kind::Object);
        ASSERT_EQ(size_t{6}, validation.object.size());
        ASSERT_TRUE(validation.at("name").kind == Json::Kind::String);
        ASSERT_TRUE(validation.at("inputEncoding").kind == Json::Kind::String);
        ASSERT_TRUE(validation.at("inputHex").kind == Json::Kind::String);
        ASSERT_TRUE(validation.at("accepted").kind == Json::Kind::Boolean);
        ASSERT_TRUE(validation.at("error").kind == Json::Kind::Null ||
                    validation.at("error").kind == Json::Kind::String);
        if (!validation.at("accepted").boolean) continue;
        ASSERT_TRUE(validation.at("seedHex").kind == Json::Kind::String);
        ASSERT_STR_EQ("utf8-hex", validation.at("inputEncoding").text);
        const auto password = hexBytes(validation.at("inputHex").text);
        assertSeed(reviewOwner, password, "review-owner", validation.at("seedHex").text);
        ++acceptedLocations;
        ++assertedLocations;
    }
    ASSERT_EQ(size_t{7}, acceptedLocations);
    ASSERT_EQ(size_t{10}, assertedLocations);
#endif
}

TEST_CASE(SdnVectors, FrozenLegacyPasswordSeed) {
    const Json root = JsonParser(loadFixture()).parse();
#if HD_WALLET_FIPS_MODE
    SKIP_TEST("legacy profile is intentionally unavailable in FIPS mode");
#else
    const Json& legacyIdentities = root.at("legacyIdentities");
    ASSERT_TRUE(legacyIdentities.kind == Json::Kind::Array);
    ASSERT_TRUE(!legacyIdentities.array.empty());
    const Json& legacy = legacyIdentities.array.front();
    ASSERT_TRUE(legacy.kind == Json::Kind::Object);
    ASSERT_EQ(size_t{7}, legacy.object.size());
    ASSERT_STR_EQ("legacy-fast-password", legacy.at("name").text);
    ASSERT_STR_EQ("sdn-fast-password-auth-v1-legacy",
                  legacy.at("identityScheme").text);
    ASSERT_STR_EQ("password-fast-v1-legacy", legacy.at("seedProfile").text);
    const Json& source = legacy.at("source");
    ASSERT_TRUE(source.kind == Json::Kind::Object);
    ASSERT_EQ(size_t{5}, source.object.size());
    ASSERT_STR_EQ("password", source.at("kind").text);
    const auto username = hexBytes(source.at("rawUsernameUtf8Hex").text);
    const auto password = hexBytes(source.at("passwordUtf8Hex").text);
    auto result = hd_wallet::sdn::derive_legacy_password_seed(byteSpan(username), byteSpan(password));
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    const auto& seed = std::get<PasswordSeed>(result);
    ASSERT_EQ(size_t{64}, seed.bytes.size());
    const auto expected = hexBytes(legacy.at("seedHex").text);
    ASSERT_EQ(size_t{64}, expected.size());
    ASSERT_BYTES_EQ(expected.data(), seed.bytes.data(), expected.size());
#endif
}

TEST_CASE(SdnVectors, IdentityDescriptorsMatchEveryFrozenAccountLiteral) {
    const Json root = JsonParser(loadFixture()).parse();
    const Json& newIdentity = root.at("newIdentity");
    const Json& passwordSource = newIdentity.at("passwordVectors").array.front();
    const auto username = hexBytes(passwordSource.at("rawUsernameUtf8Hex").text);
    const auto password = hexBytes(passwordSource.at("passwordUtf8Hex").text);
#if HD_WALLET_FIPS_MODE
    auto unavailable = hd_wallet::sdn::derive_password_identity(
        byteSpan(username), byteSpan(password), 0);
    ASSERT_TRUE(std::holds_alternative<hd_wallet::sdn::IdentityError>(unavailable));
    ASSERT_TRUE(std::get<hd_wallet::sdn::IdentityError>(unavailable) ==
                hd_wallet::sdn::IdentityError::FipsNotAllowed);
#else
    const Json& accounts = newIdentity.at("accounts");
    ASSERT_EQ(size_t{2}, accounts.array.size());
    for (const Json& account : accounts.array) {
        const uint32_t index = uint32Value(account.at("index"));
        const auto handle = take(hd_wallet::sdn::derive_password_identity(
            byteSpan(username), byteSpan(password), index));
        const auto identity = take(hd_wallet::sdn::describe_identity(handle));
        ASSERT_STR_EQ(newIdentity.at("identityScheme").text, identity.identity_scheme);
        ASSERT_STR_EQ(newIdentity.at("seedProfile").text, identity.seed_profile);
        ASSERT_EQ(index, identity.account_index);
        ASSERT_STR_EQ(account.at("accountXpub").text, identity.account_xpub);
        ASSERT_STR_EQ(account.at("peerId").text, identity.account_peer_id);
        ASSERT_STR_EQ(account.at("fingerprint").text,
                      test::bytesToHex(identity.account_fingerprint));
        ASSERT_EQ(size_t{3}, identity.keys.size());

        const auto& auth = descriptorFor(identity, hd_wallet::sdn::Purpose::SdnAuthentication);
        ASSERT_STR_EQ(account.at("authentication").at("path").text, auth.path);
        ASSERT_STR_EQ(account.at("authentication").at("publicKeyHex").text,
                      test::bytesToHex(auth.public_key));
        ASSERT_STR_EQ(account.at("authentication").at("keyId").text, auth.key_id);
        const auto& contact = descriptorFor(identity, hd_wallet::sdn::Purpose::ContactEncryption);
        ASSERT_STR_EQ(account.at("contactEncryption").at("path").text, contact.path);
        ASSERT_STR_EQ(account.at("contactEncryption").at("publicKeyHex").text,
                      test::bytesToHex(contact.public_key));
        const auto& approval = descriptorFor(identity, hd_wallet::sdn::Purpose::AssetReviewApproval);
        ASSERT_STR_EQ(account.at("assetReviewApproval").at("path").text, approval.path);
        ASSERT_STR_EQ(account.at("assetReviewApproval").at("publicKeyHex").text,
                      test::bytesToHex(approval.public_key));
        ASSERT_STR_EQ(account.at("assetReviewApproval").at("keyId").text,
                      approval.key_id);
        hd_wallet::sdn::destroy_identity(handle);
    }

    const Json& legacyIdentities = root.at("legacyIdentities");
    ASSERT_EQ(size_t{2}, legacyIdentities.array.size());
    for (const Json& legacy : legacyIdentities.array) {
        for (const Json& account : legacy.at("accounts").array) {
            const uint32_t index = uint32Value(account.at("index"));
            hd_wallet::sdn::IdentityHandle handle = 0;
            if (legacy.at("source").at("kind").text == "password") {
                const auto legacyUsername = hexBytes(
                    legacy.at("source").at("rawUsernameUtf8Hex").text);
                const auto legacyPassword = hexBytes(
                    legacy.at("source").at("passwordUtf8Hex").text);
                handle = take(hd_wallet::sdn::derive_legacy_password_identity(
                    byteSpan(legacyUsername), byteSpan(legacyPassword), index));
            } else {
                const auto mnemonic = utf8Bytes(legacy.at("source").at("mnemonic").text);
                handle = take(hd_wallet::sdn::import_legacy_mnemonic_identity(
                    byteSpan(mnemonic), index));
            }
            const auto identity = take(hd_wallet::sdn::describe_identity(handle));
            ASSERT_STR_EQ(legacy.at("identityScheme").text, identity.identity_scheme);
            ASSERT_STR_EQ(legacy.at("seedProfile").text, identity.seed_profile);
            ASSERT_STR_EQ(legacy.at("rootPublicIdentity").at("accountXpub").text,
                          identity.account_xpub);
            ASSERT_STR_EQ(legacy.at("rootPublicIdentity").at("peerId").text,
                          identity.account_peer_id);
            ASSERT_STR_EQ(legacy.at("rootPublicIdentity").at("fingerprint").text,
                          test::bytesToHex(identity.account_fingerprint));
            ASSERT_EQ(size_t{1}, identity.keys.size());
            const Json& authFixture = account.at("authentication");
            ASSERT_STR_EQ(authFixture.at("path").text, identity.keys[0].path);
            ASSERT_STR_EQ(authFixture.at("publicKeyHex").text,
                          test::bytesToHex(identity.keys[0].public_key));
            ASSERT_STR_EQ(authFixture.at("keyId").text, identity.keys[0].key_id);
            hd_wallet::sdn::destroy_identity(handle);
        }
    }

    const Json& leading = root.at("leadingZeroFingerprint");
    ASSERT_EQ(uint32_t{501}, uint32Value(leading.at("accountIndex")));
    ASSERT_STR_EQ("00611cc1", leading.at("fingerprint").text);
    auto rejected = hd_wallet::sdn::derive_password_identity(
        byteSpan(username), byteSpan(password), uint32Value(leading.at("accountIndex")));
    ASSERT_TRUE(std::holds_alternative<hd_wallet::sdn::IdentityError>(rejected));
    ASSERT_TRUE(std::get<hd_wallet::sdn::IdentityError>(rejected) ==
                hd_wallet::sdn::IdentityError::InvalidAccountIndex);
#endif
}

TEST_CASE(SdnVectors, AllNineFrozenWireSignaturesByteEqualNativeCapabilities) {
    const Json wire = JsonParser(loadFixture("sdn-operation-wire-v1.json")).parse();
    ASSERT_EQ(size_t{6}, wire.at("authenticationCases").array.size());
    ASSERT_EQ(size_t{1}, wire.at("authorityActivationCases").array.size());
    ASSERT_EQ(size_t{2}, wire.at("decisionCases").array.size());
#if HD_WALLET_FIPS_MODE
    SKIP_TEST("Task 4 operations intentionally fail closed in FIPS mode");
#else
    const Json root = JsonParser(loadFixture()).parse();
    const Json& source = root.at("newIdentity").at("passwordVectors").array.front();
    const auto username = hexBytes(source.at("rawUsernameUtf8Hex").text);
    const auto password = hexBytes(source.at("passwordUtf8Hex").text);

    const auto& authCases = wire.at("authenticationCases").array;
    for (size_t i = 0; i < authCases.size(); ++i) {
        const Json& row = authCases[i];
        const uint32_t account = uint32Value(row.at("accountIndex"));
        if (i < 4) {
            hd_wallet::sdn::IdentityHandle handle = 0;
            if (i < 2) {
                const Json& legacy = root.at("legacyIdentities").array[0];
                const auto u = hexBytes(legacy.at("source").at("rawUsernameUtf8Hex").text);
                const auto p = hexBytes(legacy.at("source").at("passwordUtf8Hex").text);
                handle = take(hd_wallet::sdn::derive_legacy_password_identity(
                    byteSpan(u), byteSpan(p), account));
            } else {
                const auto mnemonic = utf8Bytes(
                    root.at("legacyIdentities").array[1].at("source").at("mnemonic").text);
                handle = take(hd_wallet::sdn::import_legacy_mnemonic_identity(
                    byteSpan(mnemonic), account));
            }
            const auto signature = take(hd_wallet::sdn::sign_sdn_login_v1(
                handle, sequence(static_cast<uint8_t>(i * 0x20))));
            ASSERT_STR_EQ(row.at("signatureHex").text, hexArray(signature.signature));
            ASSERT_STR_EQ(row.at("authenticationKeyId").text, signature.key_id);
            hd_wallet::sdn::destroy_identity(handle);
        } else {
            const auto handle = take(hd_wallet::sdn::derive_password_identity(
                byteSpan(username), byteSpan(password), account));
            const Json& request = row.at("request");
            hd_wallet::sdn::SdnLoginV2Fields fields{
                uint32Value(request.at("protocolVersion")), request.at("audience").text,
                sequence(i == 4 ? 0x80 : 0xa0), request.at("nonce").text,
                request.at("issuedAt").text, request.at("expiresAt").text};
            const auto signature = take(hd_wallet::sdn::sign_sdn_login_v2(
                handle, fields, hd_wallet::sdn::RegistryRowId::SdnNodeConsoleV2));
            ASSERT_STR_EQ(row.at("canonicalEnvelope").text, signature.canonical_envelope);
            ASSERT_STR_EQ(row.at("signedDigestSha256").text, hexArray(signature.signed_digest));
            ASSERT_STR_EQ(row.at("signatureHex").text, hexArray(signature.signature));
            hd_wallet::sdn::destroy_identity(handle);
        }
    }

    const auto handle = take(hd_wallet::sdn::derive_password_identity(
        byteSpan(username), byteSpan(password), 0));
    const Json& activation = wire.at("authorityActivationCases").array.front();
    const Json& ar = activation.at("request");
    hd_wallet::sdn::AuthorityActivationFields activationFields{
        uint32Value(ar.at("protocolVersion")), ar.at("audience").text,
        ar.at("requestOrigin").text, ar.at("clientId").text,
        ar.at("serviceInstance").text, ar.at("purpose").text,
        ar.at("nonce").text, ar.at("issuedAt").text, ar.at("expiresAt").text,
        ar.at("publicKeyHex").text, ar.at("keyId").text,
        ar.at("identityScheme").text, ar.at("signatureProfile").text};
    const auto activationSignature = take(
        hd_wallet::sdn::sign_asset_review_authority_activation(
            handle, activationFields,
            hd_wallet::sdn::RegistryRowId::AssetReviewAuthorityActivation));
    ASSERT_STR_EQ(activation.at("canonicalEnvelope").text,
                  activationSignature.canonical_envelope);
    ASSERT_STR_EQ(activation.at("signatureHex").text,
                  hexArray(activationSignature.signature));

    for (const Json& row : wire.at("decisionCases").array) {
        const Json& request = row.at("request");
        const bool approve = request.at("decision").text == "approve";
        std::optional<hd_wallet::sdn::ReviewedTransform> transform;
        if (approve) {
            const Json& value = request.at("reviewedTransform");
            hd_wallet::sdn::ReviewedTransform parsed{};
            for (size_t i = 0; i < 3; ++i) {
                parsed.translation[i] = std::stod(value.at("translation").array[i].text);
                parsed.scale[i] = std::stod(value.at("scale").array[i].text);
            }
            for (size_t i = 0; i < 4; ++i) {
                parsed.rotation[i] = std::stod(value.at("rotation").array[i].text);
            }
            parsed.source_units = value.at("sourceUnits").text;
            parsed.meters_per_source_unit = std::stod(value.at("metersPerSourceUnit").text);
            parsed.up_axis = value.at("upAxis").text;
            transform = parsed;
        }
        std::optional<std::string> previous;
        if (request.at("previousDecisionHead").kind == Json::Kind::String) {
            previous = request.at("previousDecisionHead").text;
        }
        std::optional<std::string> note;
        std::optional<std::string> reason;
        if (approve && request.at("note").kind == Json::Kind::String) {
            note = request.at("note").text;
        }
        if (!approve) reason = request.at("reason").text;
        hd_wallet::sdn::AssetReviewDecisionFields fields{
            uint32Value(request.at("protocolVersion")), request.at("audience").text,
            request.at("requestOrigin").text, request.at("clientId").text,
            request.at("challengeId").text, request.at("nonce").text,
            request.at("issuedAt").text, request.at("expiresAt").text,
            request.at("candidateKey").text, request.at("modelCid").text,
            request.at("modelSha256").text, uint64Value(request.at("modelBytes")),
            request.at("metadataSha256").text, previous,
            approve ? hd_wallet::sdn::ReviewDecision::Approve
                    : hd_wallet::sdn::ReviewDecision::Disapprove,
            transform, note, reason};
        const auto signature = take(hd_wallet::sdn::sign_asset_review_decision(
            handle, fields, hd_wallet::sdn::RegistryRowId::AssetReviewDecision));
        ASSERT_STR_EQ(row.at("canonicalEnvelope").text, signature.canonical_envelope);
        ASSERT_STR_EQ(row.at("signedDigestSha256").text, hexArray(signature.signed_digest));
        ASSERT_STR_EQ(row.at("signatureHex").text, hexArray(signature.signature));
    }
    hd_wallet::sdn::destroy_identity(handle);
#endif
}
