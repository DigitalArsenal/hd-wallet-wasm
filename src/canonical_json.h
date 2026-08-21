/** Source-private bounded RFC 8785 JSON representation. */

#ifndef HD_WALLET_SDN_CANONICAL_JSON_H
#define HD_WALLET_SDN_CANONICAL_JSON_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace hd_wallet::sdn::jcs {

enum class JcsError : uint8_t {
    ByteLimit,
    DepthLimit,
    TokenLimit,
    StringLimit,
    InvalidUtf8,
    InvalidSyntax,
    InvalidString,
    InvalidNumber,
    NonFiniteNumber,
    Noncharacter,
    DuplicateKey,
    TrailingData,
    NotCanonical,
    OutOfMemory,
};

struct Limits {
    size_t max_bytes{131072};
    size_t max_depth{32};
    size_t max_tokens{4096};
    size_t max_string_bytes{65536};
};

class Value {
public:
    using Array = std::vector<Value>;
    using Members = std::vector<std::pair<std::string, Value>>;
    enum class Kind : uint8_t { Null, Boolean, Number, String, Array, Object };

    Value() noexcept;
    Value(std::nullptr_t) noexcept;
    Value(bool value) noexcept;
    Value(double value) noexcept;
    Value(std::string value);
    Value(const char* value);
    Value(Array value);
    Value(Members value);

    Kind kind() const noexcept;
    bool boolean() const;
    double number() const;
    const std::string& string() const;
    const Array& array() const;
    const Members& members() const;

private:
    std::variant<std::nullptr_t, bool, double, std::string, Array, Members> value_;
};

using ParseOutcome = std::variant<Value, JcsError>;
using SerializeOutcome = std::variant<std::string, JcsError>;

ParseOutcome parse_json(std::span<const uint8_t> bytes, const Limits& limits);
SerializeOutcome serialize_jcs(const Value& value, const Limits& limits);
ParseOutcome parse_exact_jcs(std::span<const uint8_t> bytes,
                             const Limits& limits);

// Validates one already-decoded UTF-8/I-JSON string using the same scalar and
// noncharacter rules as the parser and serializer.
bool valid_ijson_string(std::string_view value) noexcept;

} // namespace hd_wallet::sdn::jcs

#endif // HD_WALLET_SDN_CANONICAL_JSON_H
