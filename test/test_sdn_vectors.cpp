#include "test_framework.h"

#include "hd_wallet/password_profile.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
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

std::string loadFixture() {
    const std::string path = std::string(TEST_VECTORS_PATH) + "/sdn-wallet-vectors.v1.json";
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
