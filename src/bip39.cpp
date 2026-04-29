/**
 * @file bip39.cpp
 * @brief BIP-39 Mnemonic Code Implementation
 *
 * Implementation of BIP-39: Mnemonic code for generating deterministic keys.
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

#include "hd_wallet/bip39.h"
#include "hd_wallet/hash.h"
#include "hd_wallet/secure_rng.h"
#include "hd_wallet/secure_memory.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <bitset>
#include <cctype>
#include <cstring>
#include <sstream>

// Include wordlist from separate file
#include "bip39_wordlist.inc"

namespace hd_wallet {
namespace bip39 {

// =============================================================================
// Wordlist Functions
// =============================================================================

bool isSupportedLanguage(Language lang) {
    return lang == Language::ENGLISH;
}

const char* const* getWordlist(Language lang) {
    if (!isSupportedLanguage(lang)) {
        return nullptr;
    }
    return ENGLISH_WORDLIST;
}

int32_t findWord(const std::string& word, Language lang) {
    if (!isSupportedLanguage(lang)) {
        return -1;
    }

    const char* const* wordlist = getWordlist(lang);
    if (!wordlist) return -1;

    // Binary search since wordlist is sorted
    int32_t left = 0;
    int32_t right = WORDLIST_SIZE - 1;

    while (left <= right) {
        int32_t mid = left + (right - left) / 2;
        int cmp = word.compare(wordlist[mid]);

        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return -1;
}

std::vector<std::string> suggestWords(
    const std::string& prefix,
    Language lang,
    size_t max_suggestions
) {
    std::vector<std::string> suggestions;
    const char* const* wordlist = getWordlist(lang);
    if (!wordlist || prefix.empty()) return suggestions;

    // Convert prefix to lowercase
    std::string lower_prefix = prefix;
    std::transform(lower_prefix.begin(), lower_prefix.end(),
                   lower_prefix.begin(), ::tolower);

    for (size_t i = 0; i < WORDLIST_SIZE && suggestions.size() < max_suggestions; ++i) {
        if (std::string(wordlist[i]).substr(0, lower_prefix.size()) == lower_prefix) {
            suggestions.push_back(wordlist[i]);
        }
    }

    return suggestions;
}

// =============================================================================
// Utility Functions
// =============================================================================

std::vector<std::string> splitMnemonic(const std::string& mnemonic) {
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    std::string word;

    while (iss >> word) {
        words.push_back(word);
    }

    return words;
}

std::string joinMnemonic(const std::vector<std::string>& words) {
    if (words.empty()) return "";

    std::string result = words[0];
    for (size_t i = 1; i < words.size(); ++i) {
        result += " " + words[i];
    }

    return result;
}

std::string normalizeMnemonic(const std::string& mnemonic) {
    std::string result;
    bool in_space = true;

    for (char c : mnemonic) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!in_space && !result.empty()) {
                result += ' ';
                in_space = true;
            }
        } else {
            result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            in_space = false;
        }
    }

    // Remove trailing space
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }

    return result;
}

// =============================================================================
// Internal Helpers
// =============================================================================

namespace {

// Convert bytes to bits
std::vector<bool> bytesToBits(const uint8_t* data, size_t len) {
    std::vector<bool> bits;
    bits.reserve(len * 8);

    for (size_t i = 0; i < len; ++i) {
        for (int j = 7; j >= 0; --j) {
            bits.push_back((data[i] >> j) & 1);
        }
    }

    return bits;
}

// Convert bits to bytes
ByteVector bitsToBytes(const std::vector<bool>& bits) {
    ByteVector bytes;
    bytes.reserve((bits.size() + 7) / 8);

    for (size_t i = 0; i < bits.size(); i += 8) {
        uint8_t byte = 0;
        for (size_t j = 0; j < 8 && (i + j) < bits.size(); ++j) {
            if (bits[i + j]) {
                byte |= (1 << (7 - j));
            }
        }
        bytes.push_back(byte);
    }

    return bytes;
}

// Get 11-bit index from bits
uint16_t getWordIndex(const std::vector<bool>& bits, size_t start) {
    uint16_t index = 0;
    for (size_t i = 0; i < 11 && (start + i) < bits.size(); ++i) {
        if (bits[start + i]) {
            index |= (1 << (10 - i));
        }
    }
    return index;
}

// Validate entropy length
bool isValidEntropyLength(size_t len) {
    return len == 16 || len == 20 || len == 24 || len == 28 || len == 32;
}

// Validate word count
bool isValidWordCount(size_t count) {
    return count == 12 || count == 15 || count == 18 || count == 21 || count == 24;
}

// Get entropy size for word count
size_t entropyBytesForWords(size_t word_count) {
    return (word_count * 11 - word_count / 3) / 8;
}

} // anonymous namespace

// =============================================================================
// Mnemonic Generation
// =============================================================================

Result<std::string> generateMnemonic(size_t word_count, Language lang) {
    if (!isValidWordCount(word_count)) {
        return Result<std::string>::fail(Error::INVALID_MNEMONIC_LENGTH);
    }

    size_t entropy_bytes = entropyBytesForWords(word_count);
    ByteVector entropy(entropy_bytes);

    // Get random entropy
#ifdef HD_WALLET_WASM
    // In WASM, use the WASI bridge
    auto& bridge = WasiBridge::instance();
    if (!bridge.hasFeature(WasiFeature::RANDOM)) {
        return Result<std::string>::fail(Error::NO_ENTROPY);
    }

    int32_t bytes_written = bridge.getEntropy(entropy.data(), entropy_bytes);
    if (bytes_written < 0 || static_cast<size_t>(bytes_written) != entropy_bytes) {
        return Result<std::string>::fail(Error::NO_ENTROPY);
    }
#else
    // SECURITY FIX [VULN-09]: Use Crypto++ AutoSeededRandomPool instead of
    // std::random_device, which may be deterministic on some platforms (e.g., MinGW).
    // Also avoids discarding entropy by using full-width random bytes directly.
    SecureRandomGenerator rng;
    rng.GenerateBlock(entropy.data(), entropy_bytes);
#endif

    return entropyToMnemonic(entropy, lang);
}

Result<std::string> entropyToMnemonic(const ByteVector& entropy, Language lang) {
    if (!isSupportedLanguage(lang)) {
        return Result<std::string>::fail(Error::NOT_SUPPORTED);
    }

    if (!isValidEntropyLength(entropy.size())) {
        return Result<std::string>::fail(Error::INVALID_ENTROPY_LENGTH);
    }

    const char* const* wordlist = getWordlist(lang);
    if (!wordlist) {
        return Result<std::string>::fail(Error::NOT_SUPPORTED);
    }

    // Calculate checksum
    hash::SHA256Digest hash = hash::sha256(entropy);
    size_t checksum_bits = entropy.size() / 4; // CS = ENT / 32

    // Combine entropy + checksum bits
    std::vector<bool> bits = bytesToBits(entropy.data(), entropy.size());

    // Add checksum bits
    for (size_t i = 0; i < checksum_bits; ++i) {
        bits.push_back((hash[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Convert to mnemonic words
    std::vector<std::string> words;
    size_t word_count = bits.size() / 11;

    for (size_t i = 0; i < word_count; ++i) {
        uint16_t index = getWordIndex(bits, i * 11);
        if (index >= WORDLIST_SIZE) {
            return Result<std::string>::fail(Error::INTERNAL);
        }
        words.push_back(wordlist[index]);
    }

    return Result<std::string>::success(joinMnemonic(words));
}

Result<ByteVector> mnemonicToEntropy(const std::string& mnemonic, Language lang) {
    if (!isSupportedLanguage(lang)) {
        return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
    }

    std::string normalized = normalizeMnemonic(mnemonic);
    std::vector<std::string> words = splitMnemonic(normalized);

    if (!isValidWordCount(words.size())) {
        return Result<ByteVector>::fail(Error::INVALID_MNEMONIC_LENGTH);
    }

    // Convert words to bits
    std::vector<bool> bits;
    bits.reserve(words.size() * 11);

    for (const auto& word : words) {
        int32_t index = findWord(word, lang);
        if (index < 0) {
            return Result<ByteVector>::fail(Error::INVALID_WORD);
        }

        // Add 11 bits for this word
        for (int i = 10; i >= 0; --i) {
            bits.push_back((index >> i) & 1);
        }
    }

    // Split entropy and checksum
    size_t checksum_bits = words.size() / 3;
    size_t entropy_bits = bits.size() - checksum_bits;

    // Extract entropy bytes
    std::vector<bool> entropy_bits_vec(bits.begin(), bits.begin() + entropy_bits);
    ByteVector entropy = bitsToBytes(entropy_bits_vec);

    // Verify checksum
    hash::SHA256Digest hash = hash::sha256(entropy);

    for (size_t i = 0; i < checksum_bits; ++i) {
        bool expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
        if (bits[entropy_bits + i] != expected) {
            return Result<ByteVector>::fail(Error::INVALID_CHECKSUM);
        }
    }

    return Result<ByteVector>::success(std::move(entropy));
}

// =============================================================================
// Mnemonic Validation
// =============================================================================

Error validateMnemonic(const std::string& mnemonic, Language lang) {
    auto result = mnemonicToEntropy(mnemonic, lang);
    return result.error;
}

// =============================================================================
// Seed Derivation
// =============================================================================

Result<Bytes64> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    std::string normalized = normalizeMnemonic(mnemonic);

    // SECURITY FIX [VULN-08]: Reject non-ASCII passphrases to prevent silent
    // incompatibility with other BIP-39 implementations. BIP-39 specifies NFKD
    // Unicode normalization which this library does not implement. Using non-ASCII
    // passphrases would produce seeds that differ from other wallets, potentially
    // making funds unrecoverable on import.
    for (unsigned char c : passphrase) {
        if (c > 127) {
            return Result<Bytes64>::fail(Error::INVALID_ARGUMENT);
        }
    }

    // Salt = "mnemonic" + passphrase
    std::string salt = "mnemonic" + passphrase;

    // PBKDF2-HMAC-SHA512 with 2048 iterations
    ByteVector derived = hash::pbkdf2Sha512(
        normalized,
        salt,
        2048,
        64
    );

    if (derived.size() != 64) {
        return Result<Bytes64>::fail(Error::INTERNAL);
    }

    Bytes64 seed;
    std::copy(derived.begin(), derived.end(), seed.begin());

    // Secure wipe the intermediate
    secureWipe(derived);

    return Result<Bytes64>::success(std::move(seed));
}

Result<ByteVector> mnemonicToSeedVector(const std::string& mnemonic, const std::string& passphrase) {
    auto result = mnemonicToSeed(mnemonic, passphrase);
    if (!result.ok()) {
        return Result<ByteVector>::fail(result.error);
    }

    ByteVector vec(result.value.begin(), result.value.end());
    return Result<ByteVector>::success(std::move(vec));
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_generate(
    char* output,
    size_t output_size,
    size_t word_count,
    int32_t language
) {
    // Null pointer validation
    if (!output || output_size == 0) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Language enum validation
    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    auto result = generateMnemonic(word_count, static_cast<Language>(language));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    // Safe string copy with bounds checking (need space for null terminator)
    if (result.value.size() + 1 > output_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::memcpy(output, result.value.c_str(), result.value.size());
    output[result.value.size()] = '\0';
    return 0; // Success
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_validate(const char* mnemonic, int32_t language) {
    // Null pointer validation
    if (!mnemonic) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Language enum validation
    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    return static_cast<int32_t>(validateMnemonic(mnemonic, static_cast<Language>(language)));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_to_seed(
    const char* mnemonic,
    const char* passphrase,
    uint8_t* seed_out,
    size_t seed_size
) {
    // Null pointer validation
    if (!mnemonic || !seed_out) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    if (seed_size < 64) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto result = mnemonicToSeed(mnemonic, passphrase ? passphrase : "");
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(seed_out, result.value.data(), 64);
    return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_to_entropy(
    const char* mnemonic,
    int32_t language,
    uint8_t* entropy_out,
    size_t* entropy_size
) {
    // Null pointer validation
    if (!mnemonic || !entropy_out || !entropy_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Language enum validation
    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    auto result = mnemonicToEntropy(mnemonic, static_cast<Language>(language));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (*entropy_size < result.value.size()) {
        *entropy_size = result.value.size();
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::memcpy(entropy_out, result.value.data(), result.value.size());
    *entropy_size = result.value.size();
    return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_entropy_to_mnemonic(
    const uint8_t* entropy,
    size_t entropy_size,
    int32_t language,
    char* output,
    size_t output_size
) {
    // Null pointer validation
    if (!entropy || entropy_size == 0 || !output || output_size == 0) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Language enum validation
    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    ByteVector ent(entropy, entropy + entropy_size);
    auto result = entropyToMnemonic(ent, static_cast<Language>(language));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    // Safe string copy with bounds checking (need space for null terminator)
    if (result.value.size() + 1 > output_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::memcpy(output, result.value.c_str(), result.value.size());
    output[result.value.size()] = '\0';
    return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_mnemonic_get_wordlist(int32_t language) {
    // Returns null-terminated list where words are separated by newlines
    // This is a simplification - in practice you'd want a proper serialization
    static thread_local std::string wordlist_str;

    const char* const* wordlist = getWordlist(static_cast<Language>(language));
    if (!wordlist) return nullptr;

    wordlist_str.clear();
    for (size_t i = 0; i < WORDLIST_SIZE; ++i) {
        if (i > 0) wordlist_str += '\n';
        wordlist_str += wordlist[i];
    }

    return wordlist_str.c_str();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_suggest_word(
    const char* prefix,
    int32_t language,
    char* suggestions_out,
    size_t output_size,
    size_t max_suggestions
) {
    // Null pointer validation
    if (!prefix || !suggestions_out || output_size == 0) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Language enum validation
    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    auto suggestions = suggestWords(prefix, static_cast<Language>(language), max_suggestions);

    std::string result;
    for (size_t i = 0; i < suggestions.size(); ++i) {
        if (i > 0) result += '\n';
        result += suggestions[i];
    }

    // Safe string copy with bounds checking (need space for null terminator)
    if (result.size() + 1 > output_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::memcpy(suggestions_out, result.c_str(), result.size());
    suggestions_out[result.size()] = '\0';
    return static_cast<int32_t>(suggestions.size());
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_check_word(const char* word, int32_t language) {
    if (!word) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    if (language < 0 || language > static_cast<int32_t>(Language::ENGLISH)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    return findWord(word, static_cast<Language>(language));
}

} // namespace bip39
} // namespace hd_wallet
