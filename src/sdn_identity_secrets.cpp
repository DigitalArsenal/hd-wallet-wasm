#include "sdn_identity_internal.h"

#include "hd_wallet/libp2p.h"

#include <cryptopp/aes.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/integer.h>
#include <cryptopp/misc.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace hd_wallet::sdn::internal {
namespace {

constexpr uint32_t kHardened = 0x80000000U;
constexpr std::string_view kBitcoinSeed = "Bitcoin seed";
constexpr std::string_view kEd25519Seed = "ed25519 seed";
constexpr char kBase58[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

using DerivationBackend = void (*)(std::span<const uint8_t> key,
                                   std::span<const uint8_t> data,
                                   std::span<uint8_t, 64> output);
using SigningBackend = void (*)(std::span<const uint8_t, 32> seed,
                                std::span<const uint8_t> message,
                                std::span<uint8_t, 64> output);
using HkdfBackend = void (*)(std::span<const uint8_t> input_key_material,
                             std::span<const uint8_t> salt,
                             std::span<const uint8_t> info,
                             std::span<uint8_t> output);
using AeadSealBackend = void (*)(std::span<const uint8_t, 32> key,
                                 std::span<const uint8_t, 12> nonce,
                                 std::span<const uint8_t> plaintext,
                                 std::span<const uint8_t> aad,
                                 std::span<uint8_t> ciphertext_and_tag);
using AeadOpenBackend = bool (*)(std::span<const uint8_t, 32> key,
                                 std::span<const uint8_t, 12> nonce,
                                 std::span<const uint8_t> ciphertext_and_tag,
                                 std::span<const uint8_t> aad,
                                 std::span<uint8_t> plaintext);

#if defined(HD_WALLET_SDN_IDENTITY_TESTING) && HD_WALLET_SDN_IDENTITY_TESTING
TestingWipeObserver g_wipe_observer = nullptr;
#endif

struct Bip32Node {
    SecretBuffer private_key;
    SecretBuffer chain_code;
    std::array<uint8_t, 33> public_key{};
    uint8_t depth{0};
    uint32_t parent_fingerprint{0};
    uint32_t child_index{0};

    Bip32Node() : private_key(32), chain_code(32) {}
    Bip32Node(const Bip32Node&) = delete;
    Bip32Node& operator=(const Bip32Node&) = delete;
    Bip32Node(Bip32Node&&) noexcept = default;
    Bip32Node& operator=(Bip32Node&&) noexcept = default;
};

struct Slip10Node {
    SecretBuffer key;
    SecretBuffer chain_code;
    Slip10Node() : key(32), chain_code(32) {}
    Slip10Node(const Slip10Node&) = delete;
    Slip10Node& operator=(const Slip10Node&) = delete;
    Slip10Node(Slip10Node&&) noexcept = default;
    Slip10Node& operator=(Slip10Node&&) noexcept = default;
};

static_assert(!std::is_copy_constructible_v<Bip32Node>);
static_assert(!std::is_copy_assignable_v<Bip32Node>);
static_assert(std::is_nothrow_move_constructible_v<Bip32Node>);
static_assert(std::is_nothrow_move_assignable_v<Bip32Node>);
static_assert(!std::is_copy_constructible_v<Slip10Node>);
static_assert(!std::is_copy_assignable_v<Slip10Node>);
static_assert(std::is_nothrow_move_constructible_v<Slip10Node>);
static_assert(std::is_nothrow_move_assignable_v<Slip10Node>);

#include "bip39_wordlist.inc"

std::span<const uint8_t> asBytes(std::string_view value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}

void hmacSha512(std::span<const uint8_t> key,
                std::span<const uint8_t> data,
                std::span<uint8_t, 64> output) {
    CryptoPP::HMAC<CryptoPP::SHA512> hmac(key.data(), key.size());
    if (!data.empty()) hmac.Update(data.data(), data.size());
    hmac.Final(output.data());
}

CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& secp256k1() {
    static CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> parameters = [] {
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> result;
        result.Initialize(CryptoPP::ASN1::secp256k1());
        return result;
    }();
    return parameters;
}

const CryptoPP::Integer& secpOrder() {
    return secp256k1().GetSubgroupOrder();
}

bool validScalar(std::span<const uint8_t, 32> scalar) {
    const CryptoPP::Integer value(scalar.data(), scalar.size());
    return value > CryptoPP::Integer::Zero() && value < secpOrder();
}

std::array<uint8_t, 33> secpPublic(std::span<const uint8_t, 32> scalar) {
    const CryptoPP::Integer private_value(scalar.data(), scalar.size());
    const auto point = secp256k1().GetCurve().ScalarMultiply(
        secp256k1().GetSubgroupGenerator(), private_value);
    if (point.identity) throw std::runtime_error("invalid secp256k1 point");
    std::array<uint8_t, 33> output{};
    output[0] = point.y.IsOdd() ? 0x03 : 0x02;
    point.x.Encode(output.data() + 1, 32);
    return output;
}

std::array<uint8_t, 20> hash160(std::span<const uint8_t> bytes) {
    const auto sha = sha256_public(bytes);
    std::array<uint8_t, 20> output{};
    CryptoPP::RIPEMD160 ripemd;
    ripemd.Update(sha.data(), sha.size());
    ripemd.Final(output.data());
    return output;
}

uint32_t fingerprintWord(std::span<const uint8_t, 33> public_key) {
    const auto digest = hash160(public_key);
    return (static_cast<uint32_t>(digest[0]) << 24) |
           (static_cast<uint32_t>(digest[1]) << 16) |
           (static_cast<uint32_t>(digest[2]) << 8) |
           static_cast<uint32_t>(digest[3]);
}

std::array<uint8_t, 4> fingerprintBytes(
    std::span<const uint8_t, 33> public_key) {
    const auto digest = hash160(public_key);
    return {digest[0], digest[1], digest[2], digest[3]};
}

Bip32Node bip32Master(std::span<const uint8_t> seed,
                      DerivationBackend backend) {
    SecretBuffer digest(64);
    backend(asBytes(kBitcoinSeed), seed,
            std::span<uint8_t, 64>(digest.data(), 64));
    Bip32Node node;
    std::copy_n(digest.data(), 32, node.private_key.data());
    std::copy_n(digest.data() + 32, 32, node.chain_code.data());
    if (!validScalar(std::span<const uint8_t, 32>(node.private_key.data(), 32))) {
        throw std::runtime_error("invalid BIP32 master");
    }
    node.public_key = secpPublic(
        std::span<const uint8_t, 32>(node.private_key.data(), 32));
    return node;
}

Bip32Node bip32Child(const Bip32Node& parent,
                     uint32_t index,
                     DerivationBackend backend) {
    SecretBuffer data(37);
    if ((index & kHardened) != 0) {
        data.data()[0] = 0;
        std::copy_n(parent.private_key.data(), 32, data.data() + 1);
    } else {
        std::copy(parent.public_key.begin(), parent.public_key.end(), data.data());
    }
    data.data()[33] = static_cast<uint8_t>(index >> 24);
    data.data()[34] = static_cast<uint8_t>(index >> 16);
    data.data()[35] = static_cast<uint8_t>(index >> 8);
    data.data()[36] = static_cast<uint8_t>(index);

    SecretBuffer digest(64);
    backend(parent.chain_code.span(), data.span(),
            std::span<uint8_t, 64>(digest.data(), 64));
    const CryptoPP::Integer left(digest.data(), 32);
    if (left >= secpOrder()) throw std::runtime_error("invalid BIP32 child IL");
    const CryptoPP::Integer parent_value(parent.private_key.data(), 32);
    const CryptoPP::Integer child_value = (left + parent_value) % secpOrder();
    if (child_value.IsZero()) throw std::runtime_error("invalid BIP32 child");

    Bip32Node child;
    child_value.Encode(child.private_key.data(), 32);
    std::copy_n(digest.data() + 32, 32, child.chain_code.data());
    child.public_key = secpPublic(
        std::span<const uint8_t, 32>(child.private_key.data(), 32));
    child.depth = static_cast<uint8_t>(parent.depth + 1);
    child.parent_fingerprint = fingerprintWord(parent.public_key);
    child.child_index = index;
    return child;
}

Bip32Node bip32Path(std::span<const uint8_t> seed,
                    std::span<const uint32_t> path,
                    DerivationBackend backend) {
    Bip32Node node = bip32Master(seed, backend);
    for (const uint32_t index : path) node = bip32Child(node, index, backend);
    return node;
}

std::string base58(std::span<const uint8_t> input) {
    size_t zeros = 0;
    while (zeros < input.size() && input[zeros] == 0) ++zeros;
    std::vector<uint8_t> digits((input.size() - zeros) * 138 / 100 + 2, 0);
    size_t used = 0;
    for (size_t i = zeros; i < input.size(); ++i) {
        unsigned carry = input[i];
        size_t count = 0;
        for (auto it = digits.rbegin();
             (carry != 0 || count < used) && it != digits.rend(); ++it, ++count) {
            carry += 256U * *it;
            *it = static_cast<uint8_t>(carry % 58U);
            carry /= 58U;
        }
        used = count;
    }
    auto begin = digits.end() - static_cast<std::ptrdiff_t>(used);
    while (begin != digits.end() && *begin == 0) ++begin;
    std::string output(zeros, '1');
    for (; begin != digits.end(); ++begin) output.push_back(kBase58[*begin]);
    return output;
}

std::string serializeXpub(const Bip32Node& node) {
    std::array<uint8_t, 82> bytes{};
    bytes[0] = 0x04;
    bytes[1] = 0x88;
    bytes[2] = 0xb2;
    bytes[3] = 0x1e;
    bytes[4] = node.depth;
    bytes[5] = static_cast<uint8_t>(node.parent_fingerprint >> 24);
    bytes[6] = static_cast<uint8_t>(node.parent_fingerprint >> 16);
    bytes[7] = static_cast<uint8_t>(node.parent_fingerprint >> 8);
    bytes[8] = static_cast<uint8_t>(node.parent_fingerprint);
    bytes[9] = static_cast<uint8_t>(node.child_index >> 24);
    bytes[10] = static_cast<uint8_t>(node.child_index >> 16);
    bytes[11] = static_cast<uint8_t>(node.child_index >> 8);
    bytes[12] = static_cast<uint8_t>(node.child_index);
    std::copy_n(node.chain_code.data(), 32, bytes.data() + 13);
    std::copy(node.public_key.begin(), node.public_key.end(), bytes.data() + 45);
    const auto first = sha256_public(std::span<const uint8_t>(bytes.data(), 78));
    const auto second = sha256_public(first);
    std::copy_n(second.data(), 4, bytes.data() + 78);
    return base58(bytes);
}

std::string peerId(std::span<const uint8_t, 33> public_key) {
    std::array<char, 80> output{};
    if (hd_libp2p_peer_id_string(public_key.data(), public_key.size(),
                                 static_cast<int32_t>(Curve::SECP256K1),
                                 output.data(), output.size()) != 0) {
        throw std::runtime_error("peer id failure");
    }
    return output.data();
}

Slip10Node slip10Master(std::span<const uint8_t> seed,
                        DerivationBackend backend) {
    SecretBuffer digest(64);
    backend(asBytes(kEd25519Seed), seed,
            std::span<uint8_t, 64>(digest.data(), 64));
    Slip10Node node;
    std::copy_n(digest.data(), 32, node.key.data());
    std::copy_n(digest.data() + 32, 32, node.chain_code.data());
    return node;
}

Slip10Node slip10Child(const Slip10Node& parent,
                       uint32_t index,
                       DerivationBackend backend) {
    if ((index & kHardened) == 0) throw std::runtime_error("non-hardened SLIP10");
    SecretBuffer data(37);
    data.data()[0] = 0;
    std::copy_n(parent.key.data(), 32, data.data() + 1);
    data.data()[33] = static_cast<uint8_t>(index >> 24);
    data.data()[34] = static_cast<uint8_t>(index >> 16);
    data.data()[35] = static_cast<uint8_t>(index >> 8);
    data.data()[36] = static_cast<uint8_t>(index);
    SecretBuffer digest(64);
    backend(parent.chain_code.span(), data.span(),
            std::span<uint8_t, 64>(digest.data(), 64));
    Slip10Node child;
    std::copy_n(digest.data(), 32, child.key.data());
    std::copy_n(digest.data() + 32, 32, child.chain_code.data());
    return child;
}

Slip10Node slip10Path(std::span<const uint8_t> seed,
                      std::span<const uint32_t> path,
                      DerivationBackend backend) {
    Slip10Node node = slip10Master(seed, backend);
    for (const auto index : path) node = slip10Child(node, index, backend);
    return node;
}

std::array<uint8_t, 32> edPublic(std::span<const uint8_t, 32> seed) {
    CryptoPP::ed25519Signer signer(seed.data());
    CryptoPP::ed25519Verifier verifier(signer);
    const auto& public_key = static_cast<const CryptoPP::ed25519PublicKey&>(
        verifier.GetPublicKey());
    std::array<uint8_t, 32> output{};
    std::copy_n(public_key.GetPublicKeyBytePtr(), output.size(), output.data());
    return output;
}

std::array<uint8_t, 32> x25519Public(std::span<const uint8_t, 32> private_key) {
    CryptoPP::x25519 operation;
    std::array<uint8_t, 32> output{};
    operation.GeneratePublicKey(CryptoPP::NullRNG(), private_key.data(), output.data());
    return output;
}

int wordIndex(std::string_view word) {
    const auto begin = std::begin(ENGLISH_WORDLIST);
    const auto end = std::end(ENGLISH_WORDLIST);
    const auto found = std::lower_bound(
        begin, end, word,
        [](const char* candidate, std::string_view target) {
            return std::string_view(candidate) < target;
        });
    return found != end && word == *found ? static_cast<int>(found - begin) : -1;
}

bool validateMnemonic(const SecretBuffer& normalized) {
    SecureVector<uint16_t> indices;
    size_t begin = 0;
    while (begin < normalized.size()) {
        size_t end = begin;
        while (end < normalized.size() && normalized.data()[end] != ' ') ++end;
        const size_t length = end - begin;
        const int index = wordIndex(std::string_view(
            reinterpret_cast<const char*>(normalized.data() + begin), length));
        if (index < 0) return false;
        indices.push_back(static_cast<uint16_t>(index));
        if (end == normalized.size()) break;
        begin = end + 1;
    }
    if (!(indices.size() == 12 || indices.size() == 15 || indices.size() == 18 ||
          indices.size() == 21 || indices.size() == 24)) {
        return false;
    }
    const size_t total_bits = indices.size() * 11;
    const size_t entropy_bits = total_bits * 32 / 33;
    const size_t checksum_bits = total_bits - entropy_bits;
    SecretBuffer entropy(entropy_bits / 8);
    for (size_t bit = 0; bit < entropy_bits; ++bit) {
        const uint16_t value = indices[bit / 11];
        const uint8_t set = static_cast<uint8_t>((value >> (10 - (bit % 11))) & 1U);
        entropy.data()[bit / 8] |= static_cast<uint8_t>(set << (7 - (bit % 8)));
    }
    SecretBuffer digest(32);
    sha256_secret(entropy.span(), std::span<uint8_t, 32>(digest.data(), 32));
    for (size_t bit = 0; bit < checksum_bits; ++bit) {
        const size_t source_bit = entropy_bits + bit;
        const uint8_t actual = static_cast<uint8_t>(
            (indices[source_bit / 11] >> (10 - (source_bit % 11))) & 1U);
        const uint8_t expected = static_cast<uint8_t>((digest.data()[bit / 8] >>
                                                       (7 - (bit % 8))) & 1U);
        if (actual != expected) return false;
    }
    return true;
}

} // namespace

SecretBuffer::SecretBuffer(size_t size) : bytes_(size) {}

SecretBuffer::SecretBuffer(SecureVector<uint8_t>&& bytes) noexcept
    : bytes_(std::move(bytes)) {}

SecretBuffer::SecretBuffer(SecretBuffer&& other) noexcept
    : bytes_(std::move(other.bytes_)) {}

SecretBuffer& SecretBuffer::operator=(SecretBuffer&& other) noexcept {
    if (this != &other) {
        wipe();
        bytes_ = std::move(other.bytes_);
    }
    return *this;
}

SecretBuffer::~SecretBuffer() { wipe(); }

void SecretBuffer::wipe() noexcept {
    static_assert(std::is_nothrow_default_constructible_v<uint8_t>);
    const size_t allocation = bytes_.capacity();
    if (allocation != 0 && bytes_.data() != nullptr) {
        // This is a byte vector and allocation is its existing capacity, so
        // resize performs only nonthrowing byte value-construction and cannot
        // allocate. Construct the entire allocation before wiping it so
        // libc++'s container annotations and the C++ object-lifetime rules
        // both permit every write.
        bytes_.resize(allocation);
        secureWipe(bytes_.data(), bytes_.size() * sizeof(uint8_t));
#if defined(HD_WALLET_SDN_IDENTITY_TESTING) && HD_WALLET_SDN_IDENTITY_TESTING
        if (g_wipe_observer != nullptr) {
            const auto* allocation_bytes =
                reinterpret_cast<const volatile unsigned char*>(
                    static_cast<const void*>(bytes_.data()));
            bool all_zero = true;
            for (size_t i = 0; i < bytes_.size() * sizeof(uint8_t); ++i) {
                all_zero &= allocation_bytes[i] == 0;
            }
            g_wipe_observer(allocation, all_zero);
        }
#endif
    }
}

namespace {

DerivedIdentityMaterial deriveIdentityMaterialImpl(SecretBuffer&& seed,
                                                    IdentityKind kind,
                                                    uint32_t account_index,
                                                    DerivationBackend backend) {
    if (seed.size() != 64 || account_index > 1) {
        throw std::runtime_error("invalid identity material input");
    }
    if (backend == nullptr) throw std::runtime_error("missing derivation backend");
    DerivedIdentityMaterial result;
    result.kind = kind;
    result.account_index = account_index;
    result.seed = std::move(seed);

    if (kind == IdentityKind::PasswordV2) {
        const std::array<uint32_t, 3> account_path = {
            44U | kHardened, 0U | kHardened, account_index | kHardened};
        auto account = bip32Path(result.seed.span(), account_path, backend);
        result.account_public = account.public_key;
        result.account_fingerprint = fingerprintBytes(account.public_key);
        result.account_xpub = serializeXpub(account);
        result.account_peer_id = peerId(account.public_key);

        const auto derive_purpose = [&](uint32_t purpose) {
            const std::array<uint32_t, 5> path = {
                44U | kHardened, 0U | kHardened, account_index | kHardened,
                purpose | kHardened, 0U | kHardened};
            return slip10Path(result.seed.span(), path, backend);
        };
        auto auth = derive_purpose(0);
        auto contact = derive_purpose(1);
        auto approval = derive_purpose(2);
        result.authentication_private = std::move(auth.key);
        result.contact_private = std::move(contact.key);
        result.approval_private = std::move(approval.key);
        result.authentication_public = edPublic(std::span<const uint8_t, 32>(
            result.authentication_private.data(), 32));
        result.contact_public = x25519Public(std::span<const uint8_t, 32>(
            result.contact_private.data(), 32));
        result.approval_public = edPublic(std::span<const uint8_t, 32>(
            result.approval_private.data(), 32));
    } else {
        auto root = bip32Master(result.seed.span(), backend);
        result.account_public = root.public_key;
        result.account_fingerprint = fingerprintBytes(root.public_key);
        result.account_xpub = serializeXpub(root);
        result.account_peer_id = peerId(root.public_key);
        const std::array<uint32_t, 5> auth_path = {
            44U | kHardened, 0U | kHardened, account_index | kHardened, 0, 0};
        auto auth = bip32Path(result.seed.span(), auth_path, backend);
        result.authentication_private = std::move(auth.private_key);
        result.authentication_public = edPublic(std::span<const uint8_t, 32>(
            result.authentication_private.data(), 32));
    }
    return result;
}

void signingBackend(std::span<const uint8_t, 32> seed,
                    std::span<const uint8_t> message,
                    std::span<uint8_t, 64> output) {
    CryptoPP::ed25519Signer signer(seed.data());
    signer.SignMessage(CryptoPP::NullRNG(), message.data(), message.size(),
                       output.data());
}

std::array<uint8_t, 64> signEd25519Impl(
    std::span<const uint8_t, 32> seed,
    std::span<const uint8_t> message,
    SigningBackend backend) {
    if (backend == nullptr) throw std::runtime_error("missing signing backend");
    SecretBuffer partial(64);
    backend(seed, message, std::span<uint8_t, 64>(partial.data(), 64));
    std::array<uint8_t, 64> output{};
    std::copy_n(partial.data(), output.size(), output.data());
    return output;
}

void hkdfBackend(std::span<const uint8_t> input_key_material,
                 std::span<const uint8_t> salt,
                 std::span<const uint8_t> info,
                 std::span<uint8_t> output) {
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(output.data(), output.size(), input_key_material.data(),
                   input_key_material.size(), salt.data(), salt.size(),
                   info.data(), info.size());
}

SecretBuffer hkdfSha256Impl(std::span<const uint8_t> input_key_material,
                            std::span<const uint8_t> salt,
                            std::span<const uint8_t> info,
                            size_t output_size,
                            HkdfBackend backend) {
    if (backend == nullptr) throw std::runtime_error("missing HKDF backend");
    SecretBuffer output(output_size);
    backend(input_key_material, salt, info, output.span());
    return output;
}

void aeadSealBackend(std::span<const uint8_t, 32> key,
                     std::span<const uint8_t, 12> nonce,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::span<uint8_t> ciphertext_and_tag) {
    if (ciphertext_and_tag.size() != plaintext.size() + 16) {
        throw std::runtime_error("invalid AES-GCM seal output size");
    }
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
    encryption.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
    encryption.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
    if (!aad.empty()) encryption.Update(aad.data(), aad.size());
    if (!plaintext.empty()) {
        encryption.ProcessData(ciphertext_and_tag.data(), plaintext.data(),
                               plaintext.size());
    }
    encryption.TruncatedFinal(ciphertext_and_tag.data() + plaintext.size(), 16);
}

std::vector<uint8_t> aes256GcmSealImpl(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    AeadSealBackend backend) {
    if (backend == nullptr) throw std::runtime_error("missing AES-GCM seal backend");
    SecretBuffer partial(plaintext.size() + 16);
    backend(key, nonce, plaintext, aad, partial.span());
    return {partial.data(), partial.data() + partial.size()};
}

bool aeadOpenBackend(std::span<const uint8_t, 32> key,
                     std::span<const uint8_t, 12> nonce,
                     std::span<const uint8_t> ciphertext_and_tag,
                     std::span<const uint8_t> aad,
                     std::span<uint8_t> plaintext) {
    if (ciphertext_and_tag.size() != plaintext.size() + 16) {
        throw std::runtime_error("invalid AES-GCM open output size");
    }
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
    decryption.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
    decryption.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
    if (!aad.empty()) decryption.Update(aad.data(), aad.size());
    if (!plaintext.empty()) {
        decryption.ProcessData(plaintext.data(), ciphertext_and_tag.data(),
                               plaintext.size());
    }
    return decryption.TruncatedVerify(
        ciphertext_and_tag.data() + plaintext.size(), 16);
}

IdentityOutcome<SecretBuffer> aes256GcmOpenImpl(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad,
    AeadOpenBackend backend) {
    if (ciphertext_and_tag.size() < 16) return IdentityError::AuthenticationFailed;
    if (backend == nullptr) throw std::runtime_error("missing AES-GCM open backend");
    SecretBuffer plaintext(ciphertext_and_tag.size() - 16);
    if (!backend(key, nonce, ciphertext_and_tag, aad, plaintext.span())) {
        return IdentityError::AuthenticationFailed;
    }
    return std::move(plaintext);
}

} // namespace

DerivedIdentityMaterial derive_identity_material(SecretBuffer&& seed,
                                                  IdentityKind kind,
                                                  uint32_t account_index) {
    return deriveIdentityMaterialImpl(std::move(seed), kind, account_index,
                                      hmacSha512);
}

IdentityOutcome<SecretBuffer> derive_legacy_mnemonic_seed(
    std::span<const uint8_t> mnemonic_utf8) {
    if (mnemonic_utf8.empty() || mnemonic_utf8.size() > 1024) {
        return IdentityError::InvalidMnemonic;
    }
    try {
        SecretBuffer normalized;
        normalized.reserve(mnemonic_utf8.size());
        bool pending_space = false;
        for (const uint8_t byte : mnemonic_utf8) {
            if (byte > 0x7f) return IdentityError::InvalidMnemonic;
            if ((byte >= 0x09 && byte <= 0x0d) || byte == 0x20) {
                pending_space = !normalized.empty();
                continue;
            }
            if (pending_space) {
                normalized.push_back(' ');
                pending_space = false;
            }
            normalized.push_back(static_cast<uint8_t>(
                byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte));
        }
        if (normalized.empty() || !validateMnemonic(normalized)) {
            return IdentityError::InvalidMnemonic;
        }
        constexpr std::string_view salt = "mnemonic";
        SecretBuffer seed(64);
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
        pbkdf2.DeriveKey(seed.data(), seed.size(), 0,
                        normalized.data(), normalized.size(),
                        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                        2048, 0);
        return std::move(seed);
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

std::array<uint8_t, 32> sha256_public(std::span<const uint8_t> bytes) {
    std::array<uint8_t, 32> output{};
    CryptoPP::SHA256 hash;
    if (!bytes.empty()) hash.Update(bytes.data(), bytes.size());
    hash.Final(output.data());
    return output;
}

void sha256_secret(std::span<const uint8_t> bytes,
                   std::span<uint8_t, 32> output) {
    CryptoPP::SHA256 hash;
    if (!bytes.empty()) hash.Update(bytes.data(), bytes.size());
    hash.Final(output.data());
}

std::array<uint8_t, 64> sign_ed25519(std::span<const uint8_t, 32> seed,
                                     std::span<const uint8_t> message) {
    return signEd25519Impl(seed, message, signingBackend);
}

SecretBuffer hkdf_sha256(std::span<const uint8_t> input_key_material,
                         std::span<const uint8_t> salt,
                         std::span<const uint8_t> info,
                         size_t output_size) {
    return hkdfSha256Impl(input_key_material, salt, info, output_size,
                          hkdfBackend);
}

std::vector<uint8_t> aes256_gcm_seal(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad) {
    return aes256GcmSealImpl(key, nonce, plaintext, aad, aeadSealBackend);
}

IdentityOutcome<SecretBuffer> aes256_gcm_open(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad) {
    try {
        return aes256GcmOpenImpl(key, nonce, ciphertext_and_tag, aad,
                                 aeadOpenBackend);
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

bool constant_time_equal(std::span<const uint8_t> left,
                         std::span<const uint8_t> right) noexcept {
    if (left.size() != right.size()) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < left.size(); ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

#if defined(HD_WALLET_SDN_IDENTITY_TESTING) && HD_WALLET_SDN_IDENTITY_TESTING
void testing_set_wipe_observer(TestingWipeObserver observer) noexcept {
    g_wipe_observer = observer;
}

DerivedIdentityMaterial testing_derive_identity_material(
    SecretBuffer&& seed,
    IdentityKind kind,
    uint32_t account_index,
    TestingDerivationBackend backend) {
    return deriveIdentityMaterialImpl(std::move(seed), kind, account_index,
                                      backend);
}

std::array<uint8_t, 64> testing_sign_ed25519(
    std::span<const uint8_t, 32> seed,
    std::span<const uint8_t> message,
    TestingSigningBackend backend) {
    return signEd25519Impl(seed, message, backend);
}

SecretBuffer testing_hkdf_sha256_with_backend(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_size,
    TestingHkdfBackend backend) {
    return hkdfSha256Impl(input_key_material, salt, info, output_size, backend);
}

std::vector<uint8_t> testing_aes256_gcm_seal_with_backend(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    TestingAeadSealBackend backend) {
    return aes256GcmSealImpl(key, nonce, plaintext, aad, backend);
}

IdentityOutcome<SecretBuffer> testing_aes256_gcm_open_with_backend(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad,
    TestingAeadOpenBackend backend) {
    try {
        return aes256GcmOpenImpl(key, nonce, ciphertext_and_tag, aad, backend);
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

IdentityOutcome<std::vector<uint8_t>> testing_hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_size) {
    try {
        auto output = hkdf_sha256(ikm, salt, info, output_size);
        return std::vector<uint8_t>(output.data(), output.data() + output.size());
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

IdentityOutcome<std::vector<uint8_t>> testing_aes256_gcm_seal(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad) {
    if (key.size() != 32 || nonce.size() != 12) return IdentityError::InvalidRequest;
    try {
        return aes256_gcm_seal(
            std::span<const uint8_t, 32>(key.data(), 32),
            std::span<const uint8_t, 12>(nonce.data(), 12), plaintext, aad);
    } catch (const std::bad_alloc&) {
        return IdentityError::OutOfMemory;
    } catch (...) {
        return IdentityError::CryptoFailure;
    }
}

IdentityOutcome<std::vector<uint8_t>> testing_aes256_gcm_open(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad) {
    if (key.size() != 32 || nonce.size() != 12) return IdentityError::InvalidRequest;
    auto opened = aes256_gcm_open(
        std::span<const uint8_t, 32>(key.data(), 32),
        std::span<const uint8_t, 12>(nonce.data(), 12), ciphertext_and_tag, aad);
    if (std::holds_alternative<IdentityError>(opened)) {
        return std::get<IdentityError>(opened);
    }
    auto& plaintext = std::get<SecretBuffer>(opened);
    return std::vector<uint8_t>(plaintext.data(), plaintext.data() + plaintext.size());
}
#endif

} // namespace hd_wallet::sdn::internal
