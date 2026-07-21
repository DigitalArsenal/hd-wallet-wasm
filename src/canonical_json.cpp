#include "canonical_json.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>

namespace hd_wallet::sdn::jcs {
namespace {

enum class Utf8Result { Ok, Invalid, Noncharacter };

bool isNoncharacter(uint32_t scalar) {
    return (scalar >= 0xfdd0 && scalar <= 0xfdef) ||
           ((scalar & 0xffffU) == 0xfffeU) || ((scalar & 0xffffU) == 0xffffU);
}

Utf8Result decodeUtf8(std::span<const uint8_t> input,
                      size_t& position,
                      uint32_t& scalar) {
    if (position >= input.size()) return Utf8Result::Invalid;
    const uint8_t first = input[position++];
    size_t continuation = 0;
    if (first <= 0x7f) {
        scalar = first;
    } else if (first >= 0xc2 && first <= 0xdf) {
        scalar = first & 0x1f;
        continuation = 1;
    } else if (first >= 0xe0 && first <= 0xef) {
        if (position >= input.size()) return Utf8Result::Invalid;
        const uint8_t second = input[position];
        if ((first == 0xe0 && second < 0xa0) ||
            (first == 0xed && second >= 0xa0)) {
            return Utf8Result::Invalid;
        }
        scalar = first & 0x0f;
        continuation = 2;
    } else if (first >= 0xf0 && first <= 0xf4) {
        if (position >= input.size()) return Utf8Result::Invalid;
        const uint8_t second = input[position];
        if ((first == 0xf0 && second < 0x90) ||
            (first == 0xf4 && second >= 0x90)) {
            return Utf8Result::Invalid;
        }
        scalar = first & 0x07;
        continuation = 3;
    } else {
        return Utf8Result::Invalid;
    }
    if (input.size() - position < continuation) return Utf8Result::Invalid;
    for (size_t i = 0; i < continuation; ++i) {
        const uint8_t next = input[position++];
        if ((next & 0xc0) != 0x80) return Utf8Result::Invalid;
        scalar = (scalar << 6) | (next & 0x3f);
    }
    return isNoncharacter(scalar) ? Utf8Result::Noncharacter : Utf8Result::Ok;
}

void appendUtf8(std::string& output, uint32_t scalar) {
    if (scalar <= 0x7f) {
        output.push_back(static_cast<char>(scalar));
    } else if (scalar <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (scalar >> 6)));
        output.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else if (scalar <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (scalar >> 12)));
        output.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (scalar >> 18)));
        output.push_back(static_cast<char>(0x80 | ((scalar >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    }
}

int hexNibble(uint8_t value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

class Parser {
public:
    Parser(std::span<const uint8_t> input, const Limits& limits)
        : input_(input), limits_(limits) {}

    ParseOutcome parse() {
        if (input_.size() > limits_.max_bytes) return JcsError::ByteLimit;
        if (input_.size() >= 3 && input_[0] == 0xef && input_[1] == 0xbb &&
            input_[2] == 0xbf) {
            return JcsError::InvalidSyntax;
        }
        size_t utf8_position = 0;
        while (utf8_position < input_.size()) {
            uint32_t scalar = 0;
            const auto decoded = decodeUtf8(input_, utf8_position, scalar);
            if (decoded == Utf8Result::Invalid) return JcsError::InvalidUtf8;
            if (decoded == Utf8Result::Noncharacter) return JcsError::Noncharacter;
        }
        skipWhitespace();
        auto value = parseValue(1);
        if (std::holds_alternative<JcsError>(value)) return std::get<JcsError>(value);
        skipWhitespace();
        if (position_ != input_.size()) return JcsError::TrailingData;
        return std::move(std::get<Value>(value));
    }

private:
    ParseOutcome parseValue(size_t depth) {
        if (depth > limits_.max_depth) return JcsError::DepthLimit;
        if (++tokens_ > limits_.max_tokens) return JcsError::TokenLimit;
        skipWhitespace();
        if (position_ >= input_.size()) return JcsError::InvalidSyntax;
        switch (input_[position_]) {
            case 'n': return literal("null", Value(nullptr));
            case 't': return literal("true", Value(true));
            case 'f': return literal("false", Value(false));
            case '"': {
                auto string = parseString();
                if (std::holds_alternative<JcsError>(string)) {
                    return std::get<JcsError>(string);
                }
                return Value(std::move(std::get<std::string>(string)));
            }
            case '[': return parseArray(depth);
            case '{': return parseObject(depth);
            default: return parseNumber();
        }
    }

    ParseOutcome literal(std::string_view expected, Value value) {
        if (input_.size() - position_ < expected.size() ||
            !std::equal(expected.begin(), expected.end(), input_.begin() +
                                                     static_cast<std::ptrdiff_t>(position_))) {
            return JcsError::InvalidSyntax;
        }
        position_ += expected.size();
        return value;
    }

    ParseOutcome parseArray(size_t depth) {
        ++position_;
        Value::Array values;
        skipWhitespace();
        if (consume(']')) return Value(std::move(values));
        while (true) {
            auto value = parseValue(depth + 1);
            if (std::holds_alternative<JcsError>(value)) return std::get<JcsError>(value);
            values.push_back(std::move(std::get<Value>(value)));
            skipWhitespace();
            if (consume(']')) return Value(std::move(values));
            if (!consume(',')) return JcsError::InvalidSyntax;
        }
    }

    ParseOutcome parseObject(size_t depth) {
        ++position_;
        Value::Members members;
        skipWhitespace();
        if (consume('}')) return Value(std::move(members));
        while (true) {
            skipWhitespace();
            if (position_ >= input_.size() || input_[position_] != '"') {
                return JcsError::InvalidSyntax;
            }
            auto key = parseString();
            if (std::holds_alternative<JcsError>(key)) return std::get<JcsError>(key);
            std::string decoded = std::move(std::get<std::string>(key));
            if (std::any_of(members.begin(), members.end(),
                            [&decoded](const auto& member) {
                                return member.first == decoded;
                            })) {
                return JcsError::DuplicateKey;
            }
            skipWhitespace();
            if (!consume(':')) return JcsError::InvalidSyntax;
            auto value = parseValue(depth + 1);
            if (std::holds_alternative<JcsError>(value)) return std::get<JcsError>(value);
            members.emplace_back(std::move(decoded),
                                 std::move(std::get<Value>(value)));
            skipWhitespace();
            if (consume('}')) return Value(std::move(members));
            if (!consume(',')) return JcsError::InvalidSyntax;
        }
    }

    std::variant<std::string, JcsError> parseString() {
        if (!consume('"')) return JcsError::InvalidString;
        std::string output;
        while (position_ < input_.size()) {
            const uint8_t byte = input_[position_];
            if (byte == '"') {
                ++position_;
                if (output.size() > limits_.max_string_bytes) return JcsError::StringLimit;
                return output;
            }
            if (byte < 0x20) return JcsError::InvalidString;
            if (byte == '\\') {
                ++position_;
                if (position_ >= input_.size()) return JcsError::InvalidString;
                const uint8_t escaped = input_[position_++];
                switch (escaped) {
                    case '"': output.push_back('"'); break;
                    case '\\': output.push_back('\\'); break;
                    case '/': output.push_back('/'); break;
                    case 'b': output.push_back('\b'); break;
                    case 'f': output.push_back('\f'); break;
                    case 'n': output.push_back('\n'); break;
                    case 'r': output.push_back('\r'); break;
                    case 't': output.push_back('\t'); break;
                    case 'u': {
                        auto unit = parseHexUnit();
                        if (!unit.has_value()) return JcsError::InvalidString;
                        uint32_t scalar = *unit;
                        if (scalar >= 0xd800 && scalar <= 0xdbff) {
                            if (input_.size() - position_ < 6 ||
                                input_[position_] != '\\' || input_[position_ + 1] != 'u') {
                                return JcsError::InvalidString;
                            }
                            position_ += 2;
                            auto low = parseHexUnit();
                            if (!low.has_value() || *low < 0xdc00 || *low > 0xdfff) {
                                return JcsError::InvalidString;
                            }
                            scalar = 0x10000 + ((scalar - 0xd800) << 10) + (*low - 0xdc00);
                        } else if (scalar >= 0xdc00 && scalar <= 0xdfff) {
                            return JcsError::InvalidString;
                        }
                        if (isNoncharacter(scalar)) return JcsError::Noncharacter;
                        appendUtf8(output, scalar);
                        break;
                    }
                    default: return JcsError::InvalidString;
                }
            } else if (byte < 0x80) {
                output.push_back(static_cast<char>(byte));
                ++position_;
            } else {
                const size_t begin = position_;
                uint32_t scalar = 0;
                const Utf8Result decoded = decodeUtf8(input_, position_, scalar);
                if (decoded == Utf8Result::Invalid) return JcsError::InvalidUtf8;
                if (decoded == Utf8Result::Noncharacter) return JcsError::Noncharacter;
                output.append(reinterpret_cast<const char*>(input_.data() + begin),
                              position_ - begin);
            }
            if (output.size() > limits_.max_string_bytes) return JcsError::StringLimit;
        }
        return JcsError::InvalidString;
    }

    std::optional<uint16_t> parseHexUnit() {
        if (input_.size() - position_ < 4) return std::nullopt;
        uint16_t value = 0;
        for (size_t i = 0; i < 4; ++i) {
            const int nibble = hexNibble(input_[position_++]);
            if (nibble < 0) return std::nullopt;
            value = static_cast<uint16_t>((value << 4) | nibble);
        }
        return value;
    }

    ParseOutcome parseNumber() {
        const size_t begin = position_;
        if (consume('-') && position_ >= input_.size()) return JcsError::InvalidNumber;
        if (consume('0')) {
            if (position_ < input_.size() && input_[position_] >= '0' &&
                input_[position_] <= '9') {
                return JcsError::InvalidNumber;
            }
        } else {
            if (position_ >= input_.size() || input_[position_] < '1' ||
                input_[position_] > '9') {
                return JcsError::InvalidNumber;
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        if (consume('.')) {
            if (position_ >= input_.size() || input_[position_] < '0' ||
                input_[position_] > '9') {
                return JcsError::InvalidNumber;
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < input_.size() &&
            (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= input_.size() || input_[position_] < '0' ||
                input_[position_] > '9') {
                return JcsError::InvalidNumber;
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        const char* first = reinterpret_cast<const char*>(input_.data() + begin);
        const char* last = reinterpret_cast<const char*>(input_.data() + position_);
        double value = 0;
        const auto converted = std::from_chars(first, last, value,
                                               std::chars_format::general);
        if (converted.ec != std::errc{} || converted.ptr != last) {
            return JcsError::InvalidNumber;
        }
        if (!std::isfinite(value)) return JcsError::InvalidNumber;
        return Value(value);
    }

    void skipWhitespace() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\n' || input_[position_] == '\r')) {
            ++position_;
        }
    }

    bool consume(uint8_t expected) {
        if (position_ < input_.size() && input_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    std::span<const uint8_t> input_;
    const Limits& limits_;
    size_t position_{0};
    size_t tokens_{0};
};

std::vector<uint16_t> utf16Units(std::string_view value) {
    std::span<const uint8_t> input(
        reinterpret_cast<const uint8_t*>(value.data()), value.size());
    std::vector<uint16_t> units;
    units.reserve(value.size());
    size_t position = 0;
    while (position < input.size()) {
        uint32_t scalar = 0;
        if (decodeUtf8(input, position, scalar) != Utf8Result::Ok) return {};
        if (scalar <= 0xffff) {
            units.push_back(static_cast<uint16_t>(scalar));
        } else {
            scalar -= 0x10000;
            units.push_back(static_cast<uint16_t>(0xd800 + (scalar >> 10)));
            units.push_back(static_cast<uint16_t>(0xdc00 + (scalar & 0x3ff)));
        }
    }
    return units;
}

bool utf16Less(const std::string& left, const std::string& right) {
    return utf16Units(left) < utf16Units(right);
}

std::string formatNumber(double value) {
    if (value == 0) return "0";
    char buffer[128];
    const auto converted = std::to_chars(buffer, buffer + sizeof(buffer),
                                         value, std::chars_format::general);
    if (converted.ec != std::errc{}) throw std::runtime_error("number format");
    std::string raw(buffer, converted.ptr);
    bool negative = false;
    size_t start = 0;
    if (!raw.empty() && raw.front() == '-') {
        negative = true;
        start = 1;
    }
    size_t exponentPosition = raw.find_first_of("eE", start);
    std::string mantissa = raw.substr(start, exponentPosition - start);
    int exponent = 0;
    if (exponentPosition != std::string::npos) {
        std::string_view exponentText(raw.data() + exponentPosition + 1,
                                      raw.size() - exponentPosition - 1);
        bool exponentNegative = false;
        if (!exponentText.empty() &&
            (exponentText.front() == '+' || exponentText.front() == '-')) {
            exponentNegative = exponentText.front() == '-';
            exponentText.remove_prefix(1);
        }
        const auto parsed = std::from_chars(exponentText.data(),
                                            exponentText.data() + exponentText.size(),
                                            exponent);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != exponentText.data() + exponentText.size()) {
            throw std::runtime_error("number exponent");
        }
        if (exponentNegative) exponent = -exponent;
    }
    const size_t dot = mantissa.find('.');
    int decimalPosition = dot == std::string::npos
                              ? static_cast<int>(mantissa.size())
                              : static_cast<int>(dot);
    std::string digits = mantissa;
    if (dot != std::string::npos) digits.erase(dot, 1);
    const int k = decimalPosition + exponent;

    std::string result;
    if (negative) result.push_back('-');
    if (k > 0 && k <= 21) {
        if (static_cast<size_t>(k) >= digits.size()) {
            result += digits;
            result.append(static_cast<size_t>(k) - digits.size(), '0');
        } else {
            result.append(digits.data(), static_cast<size_t>(k));
            result.push_back('.');
            result.append(digits.data() + k, digits.size() - static_cast<size_t>(k));
        }
    } else if (k <= 0 && k > -6) {
        result += "0.";
        result.append(static_cast<size_t>(-k), '0');
        result += digits;
    } else {
        result.push_back(digits.front());
        if (digits.size() > 1) {
            result.push_back('.');
            result.append(digits.data() + 1, digits.size() - 1);
        }
        const int scientificExponent = k - 1;
        result.push_back('e');
        if (scientificExponent >= 0) result.push_back('+');
        result += std::to_string(scientificExponent);
    }
    return result;
}

class Serializer {
public:
    explicit Serializer(const Limits& limits) : limits_(limits) {}

    SerializeOutcome serialize(const Value& value) {
        try {
            auto error = append(value, 1);
            if (error.has_value()) return *error;
            return std::move(output_);
        } catch (const std::bad_alloc&) {
            return JcsError::OutOfMemory;
        } catch (...) {
            return JcsError::InvalidNumber;
        }
    }

private:
    std::optional<JcsError> append(const Value& value, size_t depth) {
        if (depth > limits_.max_depth) return JcsError::DepthLimit;
        if (++tokens_ > limits_.max_tokens) return JcsError::TokenLimit;
        switch (value.kind()) {
            case Value::Kind::Null: return literal("null");
            case Value::Kind::Boolean:
                return literal(value.boolean() ? "true" : "false");
            case Value::Kind::Number:
                if (!std::isfinite(value.number())) return JcsError::NonFiniteNumber;
                return literal(formatNumber(value.number()));
            case Value::Kind::String:
                return appendString(value.string());
            case Value::Kind::Array: {
                if (auto error = literal("[")) return error;
                bool first = true;
                for (const auto& child : value.array()) {
                    if (!first) {
                        if (auto error = literal(",")) return error;
                    }
                    first = false;
                    if (auto error = append(child, depth + 1)) return error;
                }
                return literal("]");
            }
            case Value::Kind::Object: {
                std::vector<const std::pair<std::string, Value>*> sorted;
                sorted.reserve(value.members().size());
                for (const auto& member : value.members()) {
                    if (!valid_ijson_string(member.first)) return classifyInvalid(member.first);
                    if (std::any_of(sorted.begin(), sorted.end(), [&member](const auto* prior) {
                            return prior->first == member.first;
                        })) {
                        return JcsError::DuplicateKey;
                    }
                    sorted.push_back(&member);
                }
                std::sort(sorted.begin(), sorted.end(), [](const auto* left, const auto* right) {
                    return utf16Less(left->first, right->first);
                });
                if (auto error = literal("{")) return error;
                bool first = true;
                for (const auto* member : sorted) {
                    if (!first) {
                        if (auto error = literal(",")) return error;
                    }
                    first = false;
                    if (auto error = appendString(member->first)) return error;
                    if (auto error = literal(":")) return error;
                    if (auto error = append(member->second, depth + 1)) return error;
                }
                return literal("}");
            }
        }
        return JcsError::InvalidSyntax;
    }

    JcsError classifyInvalid(std::string_view value) {
        std::span<const uint8_t> input(
            reinterpret_cast<const uint8_t*>(value.data()), value.size());
        size_t position = 0;
        while (position < input.size()) {
            uint32_t scalar = 0;
            const auto decoded = decodeUtf8(input, position, scalar);
            if (decoded == Utf8Result::Noncharacter) return JcsError::Noncharacter;
            if (decoded == Utf8Result::Invalid) return JcsError::InvalidUtf8;
        }
        return JcsError::InvalidString;
    }

    std::optional<JcsError> appendString(std::string_view value) {
        if (value.size() > limits_.max_string_bytes) return JcsError::StringLimit;
        if (!valid_ijson_string(value)) return classifyInvalid(value);
        if (auto error = literal("\"")) return error;
        static constexpr char hex[] = "0123456789abcdef";
        for (const unsigned char byte : value) {
            switch (byte) {
                case '"': if (auto error = literal("\\\"")) return error; break;
                case '\\': if (auto error = literal("\\\\")) return error; break;
                case '\b': if (auto error = literal("\\b")) return error; break;
                case '\t': if (auto error = literal("\\t")) return error; break;
                case '\n': if (auto error = literal("\\n")) return error; break;
                case '\f': if (auto error = literal("\\f")) return error; break;
                case '\r': if (auto error = literal("\\r")) return error; break;
                default:
                    if (byte < 0x20) {
                        char escaped[] = {'\\', 'u', '0', '0', hex[byte >> 4],
                                          hex[byte & 0x0f]};
                        if (auto error = literal(std::string_view(escaped, sizeof(escaped)))) {
                            return error;
                        }
                    } else {
                        if (output_.size() + 1 > limits_.max_bytes) return JcsError::ByteLimit;
                        output_.push_back(static_cast<char>(byte));
                    }
            }
        }
        return literal("\"");
    }

    std::optional<JcsError> literal(std::string_view text) {
        if (output_.size() > limits_.max_bytes ||
            text.size() > limits_.max_bytes - output_.size()) {
            return JcsError::ByteLimit;
        }
        output_.append(text);
        return std::nullopt;
    }

    const Limits& limits_;
    std::string output_;
    size_t tokens_{0};
};

} // namespace

Value::Value() noexcept : value_(nullptr) {}
Value::Value(std::nullptr_t) noexcept : value_(nullptr) {}
Value::Value(bool value) noexcept : value_(value) {}
Value::Value(double value) noexcept : value_(value) {}
Value::Value(std::string value) : value_(std::move(value)) {}
Value::Value(const char* value) : value_(std::string(value)) {}
Value::Value(Array value) : value_(std::move(value)) {}
Value::Value(Members value) : value_(std::move(value)) {}

Value::Kind Value::kind() const noexcept {
    return static_cast<Kind>(value_.index());
}

bool Value::boolean() const { return std::get<bool>(value_); }
double Value::number() const { return std::get<double>(value_); }
const std::string& Value::string() const { return std::get<std::string>(value_); }
const Value::Array& Value::array() const { return std::get<Array>(value_); }
const Value::Members& Value::members() const { return std::get<Members>(value_); }

bool valid_ijson_string(std::string_view value) noexcept {
    std::span<const uint8_t> input(
        reinterpret_cast<const uint8_t*>(value.data()), value.size());
    size_t position = 0;
    while (position < input.size()) {
        uint32_t scalar = 0;
        if (decodeUtf8(input, position, scalar) != Utf8Result::Ok) return false;
    }
    return true;
}

ParseOutcome parse_json(std::span<const uint8_t> bytes, const Limits& limits) {
    try {
        return Parser(bytes, limits).parse();
    } catch (const std::bad_alloc&) {
        return JcsError::OutOfMemory;
    } catch (...) {
        return JcsError::InvalidSyntax;
    }
}

SerializeOutcome serialize_jcs(const Value& value, const Limits& limits) {
    return Serializer(limits).serialize(value);
}

ParseOutcome parse_exact_jcs(std::span<const uint8_t> bytes,
                             const Limits& limits) {
    auto parsed = parse_json(bytes, limits);
    if (std::holds_alternative<JcsError>(parsed)) return std::get<JcsError>(parsed);
    auto serialized = serialize_jcs(std::get<Value>(parsed), limits);
    if (std::holds_alternative<JcsError>(serialized)) {
        return std::get<JcsError>(serialized);
    }
    const std::string& canonical = std::get<std::string>(serialized);
    if (canonical.size() != bytes.size() ||
        !std::equal(canonical.begin(), canonical.end(), bytes.begin())) {
        return JcsError::NotCanonical;
    }
    return std::move(std::get<Value>(parsed));
}

} // namespace hd_wallet::sdn::jcs
