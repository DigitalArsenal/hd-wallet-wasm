#include "test_framework.h"

#include "canonical_json.h"
#include "hd_wallet/sdn_identity.h"
#include "sdn_identity_internal.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <variant>
#include <vector>

#ifndef TEST_VECTORS_PATH
#define TEST_VECTORS_PATH "."
#endif

namespace {

using namespace hd_wallet::sdn;

std::span<const uint8_t> bytes(const std::string& value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}

std::span<const uint8_t> bytes(const std::vector<uint8_t>& value) {
    return {value.data(), value.size()};
}

std::string readFixture(const std::string& name) {
    const std::string path = std::string(TEST_VECTORS_PATH) + "/" + name;
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("required fixture missing: " + path);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

std::string base32Lower(std::span<const uint8_t> input) {
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    std::string output;
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t byte : input) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output.push_back(alphabet[(buffer >> bits) & 0x1f]);
        }
        buffer = bits == 0 ? 0 : buffer & ((1U << bits) - 1U);
    }
    if (bits != 0) output.push_back(alphabet[(buffer << (5 - bits)) & 0x1f]);
    return output;
}

std::string rawSha256Cid(uint8_t version,
                         uint8_t codec,
                         uint8_t hash_code,
                         uint8_t digest_length,
                         uint8_t digest_byte) {
    std::array<uint8_t, 36> cid{};
    cid[0] = version;
    cid[1] = codec;
    cid[2] = hash_code;
    cid[3] = digest_length;
    std::fill(cid.begin() + 4, cid.end(), digest_byte);
    return "b" + base32Lower(cid);
}

template <typename T>
T take(IdentityOutcome<T>&& outcome) {
    ASSERT_TRUE(std::holds_alternative<T>(outcome));
    return std::move(std::get<T>(outcome));
}

template <typename T>
void assertError(IdentityError expected, const IdentityOutcome<T>& outcome) {
    ASSERT_TRUE(std::holds_alternative<IdentityError>(outcome));
    ASSERT_EQ(static_cast<uint16_t>(expected),
              static_cast<uint16_t>(std::get<IdentityError>(outcome)));
}

IdentityHandle deriveNew(uint32_t account = 0) {
    return take(derive_password_identity(
        bytes(std::string("  ALICE_01  ")),
        bytes(std::string("Correct Horse Battery Staple!")), account));
}

IdentityHandle deriveLegacy(uint32_t account = 0) {
    return take(derive_legacy_password_identity(
        bytes(std::string("fixture-legacy-user")),
        bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), account));
}

IdentityHandle deriveMnemonic(uint32_t account = 0) {
    return take(import_legacy_mnemonic_identity(bytes(std::string(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about")), account));
}

std::array<uint8_t, 32> sequence(uint8_t first) {
    std::array<uint8_t, 32> result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<uint8_t>(first + i);
    }
    return result;
}

void assertRaw(const RawSignature& signature,
               const std::string& keyId,
               const std::string& scheme,
               const std::string& expectedHex) {
    ASSERT_EQ(uint32_t{1}, signature.schema_version);
    ASSERT_STR_EQ(keyId, signature.key_id);
    ASSERT_STR_EQ(scheme, signature.identity_scheme);
    ASSERT_STR_EQ("ed25519", signature.algorithm);
    ASSERT_EQ(static_cast<int>(KeyEncoding::Raw), static_cast<int>(signature.encoding));
    ASSERT_STR_EQ("ed25519-raw-32-v1", signature.signature_profile);
    ASSERT_STR_EQ(expectedHex, test::bytesToHex(signature.signature));
}

void assertCanonical(const CanonicalSignature& signature,
                     const std::string& keyId,
                     const std::string& envelope,
                     const std::string& digest,
                     const std::string& expectedHex) {
    ASSERT_EQ(uint32_t{1}, signature.schema_version);
    ASSERT_STR_EQ(keyId, signature.key_id);
    ASSERT_STR_EQ(std::string(kIdentityScheme), signature.identity_scheme);
    ASSERT_STR_EQ("ed25519", signature.algorithm);
    ASSERT_EQ(static_cast<int>(KeyEncoding::Raw), static_cast<int>(signature.encoding));
    ASSERT_STR_EQ("ed25519-over-sha256-jcs-v1", signature.signature_profile);
    ASSERT_STR_EQ(envelope, signature.canonical_envelope);
    ASSERT_STR_EQ(digest, test::bytesToHex(signature.signed_digest));
    ASSERT_STR_EQ(expectedHex, test::bytesToHex(signature.signature));
}

SdnLoginV2Fields loginRequest(uint32_t account) {
    return SdnLoginV2Fields{
        2,
        "sdn-login:sdn.spaceaware.io",
        account == 0 ? sequence(0x80) : sequence(0xa0),
        account == 0
            ? "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            : "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        account == 0 ? "2026-07-20T20:00:00.000Z" : "2026-07-20T21:00:00.000Z",
        account == 0 ? "2026-07-20T20:05:00.000Z" : "2026-07-20T21:05:00.000Z",
    };
}

AuthorityActivationFields activationRequest() {
    return AuthorityActivationFields{
        1,
        "asset-review-authority:assets.ipfs.01",
        "https://review.spacedatanetwork.org",
        "sdn-asset-review-v1",
        "assets.ipfs.01/asset-review-attestation",
        "asset-review-authority-activation",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "2026-07-20T22:00:00.000Z",
        "2026-07-20T22:05:00.000Z",
        "9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff",
        "sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d",
        "sdn-bip32-slip10-purpose-v1",
        "ed25519-over-sha256-jcs-v1",
    };
}

ReviewedTransform identityTransform() {
    return ReviewedTransform{{0, 0, 0}, {0, 0, 0, 1}, {1, 1, 1}, "Y_UP", "m", 1};
}

AssetReviewDecisionFields approveRequest() {
    return AssetReviewDecisionFields{
        1,
        "asset-review:assets.ipfs.01",
        "https://review.spacedatanetwork.org",
        "sdn-asset-review-v1",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "2026-07-20T23:00:00.000Z",
        "2026-07-20T23:05:00.000Z",
        "asset-review:spacecraft/example:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        12345,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        std::nullopt,
        ReviewDecision::Approve,
        identityTransform(),
        std::string("Synthetic fixture approval."),
        std::nullopt,
    };
}

AssetReviewDecisionFields disapproveRequest() {
    return AssetReviewDecisionFields{
        1,
        "asset-review:assets.ipfs.01",
        "https://review.spacedatanetwork.org",
        "sdn-asset-review-v1",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "2026-07-21T00:00:00.000Z",
        "2026-07-21T00:05:00.000Z",
        "asset-review:spacecraft/example:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        12345,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        std::string("5bf299ed6cc14cefe075bad165cf1e02992903f976202e87772905385df87dda"),
        ReviewDecision::Disapprove,
        std::nullopt,
        std::nullopt,
        std::string("Synthetic fixture rejection."),
    };
}

template <typename Outcome>
void assertJcsError(hd_wallet::sdn::jcs::JcsError expected, const Outcome& outcome) {
    ASSERT_TRUE(std::holds_alternative<hd_wallet::sdn::jcs::JcsError>(outcome));
    ASSERT_EQ(static_cast<int>(expected),
              static_cast<int>(std::get<hd_wallet::sdn::jcs::JcsError>(outcome)));
}

std::string serialize(const hd_wallet::sdn::jcs::Value& value) {
    auto outcome = hd_wallet::sdn::jcs::serialize_jcs(value, {});
    ASSERT_TRUE(std::holds_alternative<std::string>(outcome));
    return std::get<std::string>(std::move(outcome));
}

std::string utf8(uint32_t scalar) {
    std::string result;
    if (scalar <= 0x7f) {
        result.push_back(static_cast<char>(scalar));
    } else if (scalar <= 0x7ff) {
        result.push_back(static_cast<char>(0xc0 | (scalar >> 6)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else if (scalar <= 0xffff) {
        result.push_back(static_cast<char>(0xe0 | (scalar >> 12)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else {
        result.push_back(static_cast<char>(0xf0 | (scalar >> 18)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 12) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    }
    return result;
}

} // namespace

TEST_CASE(SdnSigning, LegacyRawV1SignaturesMatchAllFourFrozenCases) {
#if HD_WALLET_FIPS_MODE
    assertError(IdentityError::FipsNotAllowed,
                sign_sdn_login_v1(0, sequence(0)));
#else
    struct Row {
        bool mnemonic;
        uint32_t account;
        uint8_t challenge;
        const char* key_id;
        const char* scheme;
        const char* signature;
    };
    const Row rows[] = {
        {false, 0, 0x00,
         "sha256:0d5b0e5c9371eea56a7c20ff27e6c0759d93c26794a4cea91c25f0ffafc4c1da",
         "sdn-fast-password-auth-v1-legacy",
         "16afa44dee296c85350922a10e64e7d8faeb3ad77747c050794140a08974df5af7bcee1bf27fbe8eb36bea25c9c3bc4470a03dd801b36d58edd64e6e45b93203"},
        {false, 1, 0x20,
         "sha256:f39aaef64b015de3c01bbfd6561c86ea5cb9d4a822b0c982093646da353aafd5",
         "sdn-fast-password-auth-v1-legacy",
         "67fdc308b5214ea4356268b61fd030eb31a2622cc15fa332c84eb5812283ae5ea1969320cb03f7e4243e60f6e6ccea7de117fab679a92a45ad36689ec0122e0b"},
        {true, 0, 0x40,
         "sha256:840c4084865fc7153bcef07c5458e1bae11370539f3b9106542db552dcc10115",
         "sdn-bip39-auth-v1-legacy",
         "542957a9ba75ca30e639637d79575ae8a6868e1a3923a3b2f9e4e91bf99cf8134f0b9ef90a224bca094efb8b264b6a75477433c5e835699c5e0aaf972f9bbf03"},
        {true, 1, 0x60,
         "sha256:b8aece28623ce188040068c43558930c6fe4eee83c6730ea680831c64cfd1072",
         "sdn-bip39-auth-v1-legacy",
         "ea5c1aeb77a6201a49f8926cde019f5a8bfa3563b957184cc1d668f9edea3c98ac415b740dd48f6a651e2755ca637d9ecf875b059c2cc5543dbc8a7045f2f704"},
    };
    for (const auto& row : rows) {
        const IdentityHandle handle = row.mnemonic ? deriveMnemonic(row.account)
                                                    : deriveLegacy(row.account);
        assertRaw(take(sign_sdn_login_v1(handle, sequence(row.challenge))),
                  row.key_id, row.scheme, row.signature);
        destroy_identity(handle);
    }
#endif
}

TEST_CASE(SdnSigning, FipsRejectsEveryTypedSigningCapabilityBeforeLookup) {
#if HD_WALLET_FIPS_MODE
    assertError(IdentityError::FipsNotAllowed,
                sign_sdn_login_v1(0, sequence(0)));
    assertError(IdentityError::FipsNotAllowed,
                sign_sdn_login_v2(0, loginRequest(0),
                                  RegistryRowId::SdnNodeConsoleV2));
    assertError(IdentityError::FipsNotAllowed,
                sign_asset_review_authority_activation(
                    0, activationRequest(),
                    RegistryRowId::AssetReviewAuthorityActivation));
    assertError(IdentityError::FipsNotAllowed,
                sign_asset_review_decision(
                    0, approveRequest(), RegistryRowId::AssetReviewDecision));
#endif
}

TEST_CASE(SdnSigning, NewLoginV2SignaturesMatchBothFrozenCanonicalEnvelopes) {
#if !HD_WALLET_FIPS_MODE
    const std::array<std::string, 2> envelopes = {
        "{\"audience\":\"sdn-login:sdn.spaceaware.io\",\"challengeSha256\":\"82d86408530b765e46ebf47807095027e807bc08674b0de77ee5ef2fae7d0492\",\"clientId\":\"sdn-node-console-v1\",\"expiresAt\":\"2026-07-20T20:05:00.000Z\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"issuedAt\":\"2026-07-20T20:00:00.000Z\",\"keyId\":\"sha256:d997ad2bf7dbf21c490695eba54d3054628d7f7fb9037fb8145ea32b4e384b7c\",\"kind\":\"sdn-login\",\"nonce\":\"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\",\"protocolVersion\":2,\"requestOrigin\":\"https://sdn.spaceaware.io\",\"signatureProfile\":\"ed25519-over-sha256-jcs-v1\"}",
        "{\"audience\":\"sdn-login:sdn.spaceaware.io\",\"challengeSha256\":\"00e988677eecf94c0bb9233371c7c0d6f4db8ebdcdecb7c5ebaa666f17249227\",\"clientId\":\"sdn-node-console-v1\",\"expiresAt\":\"2026-07-20T21:05:00.000Z\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"issuedAt\":\"2026-07-20T21:00:00.000Z\",\"keyId\":\"sha256:72a40224fc9ba6c1ddeaa4f6da6cd53ab6015f591b76f77c984a6b7d4573b9ef\",\"kind\":\"sdn-login\",\"nonce\":\"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\",\"protocolVersion\":2,\"requestOrigin\":\"https://sdn.spaceaware.io\",\"signatureProfile\":\"ed25519-over-sha256-jcs-v1\"}",
    };
    const std::array<std::string, 2> keyIds = {
        "sha256:d997ad2bf7dbf21c490695eba54d3054628d7f7fb9037fb8145ea32b4e384b7c",
        "sha256:72a40224fc9ba6c1ddeaa4f6da6cd53ab6015f591b76f77c984a6b7d4573b9ef",
    };
    const std::array<std::string, 2> digests = {
        "d60302263a3df76a5e6d2b26603f1c8f782af0e14651f8148df55ed50238821f",
        "f48a08889a71ea1cb14771bdbc78f0ddd7cf4c5506669ec416841e3931357cf7",
    };
    const std::array<std::string, 2> signatures = {
        "8b73c59a4bcd1a04d98942857016b0a7a4f7461416a810713fe2ed6db9d13e7deab501e613519f2290f199571a54af56a1c84b6475ae1a845130178b93770905",
        "d904862fded80a90793c4a5b2610105bf6d6109da49c085bdfee34d0338a6313b65d0e1f0db2c24d401b8ce9501432288d4165885aad74827103b2f887ca7e05",
    };
    for (uint32_t account = 0; account < 2; ++account) {
        const IdentityHandle handle = deriveNew(account);
        assertCanonical(take(sign_sdn_login_v2(
                            handle, loginRequest(account), RegistryRowId::SdnNodeConsoleV2)),
                        keyIds[account], envelopes[account], digests[account], signatures[account]);
        destroy_identity(handle);
    }
#endif
}

TEST_CASE(SdnSigning, ApprovalOperationsMatchAllFrozenCanonicalEnvelopes) {
#if !HD_WALLET_FIPS_MODE
    const IdentityHandle handle = deriveNew();
    const std::string keyId =
        "sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d";
    const std::string activationEnvelope =
        "{\"audience\":\"asset-review-authority:assets.ipfs.01\",\"clientId\":\"sdn-asset-review-v1\",\"expiresAt\":\"2026-07-20T22:05:00.000Z\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"issuedAt\":\"2026-07-20T22:00:00.000Z\",\"keyId\":\"sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d\",\"kind\":\"asset-review-authority-activation\",\"nonce\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"protocolVersion\":1,\"publicKeyHex\":\"9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff\",\"purpose\":\"asset-review-authority-activation\",\"requestOrigin\":\"https://review.spacedatanetwork.org\",\"serviceInstance\":\"assets.ipfs.01/asset-review-attestation\",\"signatureProfile\":\"ed25519-over-sha256-jcs-v1\"}";
    assertCanonical(take(sign_asset_review_authority_activation(
                        handle, activationRequest(),
                        RegistryRowId::AssetReviewAuthorityActivation)),
                    keyId, activationEnvelope,
                    "3df7721fe944aba327f7288861466fc033c1f95c4ddfd456d387804ca7743dda",
                    "dc98b9e9fff436e595afed4b66038f44bac475e387321ce3e4f2290e84ee09fb9297546300e4e473bce28dd830f42a8632b034b29152e700dadba12adef3ce0a");

    const std::string approveEnvelope =
        "{\"audience\":\"asset-review:assets.ipfs.01\",\"candidateKey\":\"asset-review:spacecraft/example:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"challengeId\":\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",\"clientId\":\"sdn-asset-review-v1\",\"decision\":\"approve\",\"expiresAt\":\"2026-07-20T23:05:00.000Z\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"issuedAt\":\"2026-07-20T23:00:00.000Z\",\"keyId\":\"sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d\",\"kind\":\"asset-review-attestation\",\"metadataSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"modelBytes\":12345,\"modelCid\":\"bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi\",\"modelSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"nonce\":\"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\",\"note\":\"Synthetic fixture approval.\",\"previousDecisionHead\":null,\"protocolVersion\":1,\"purpose\":\"asset-review-approval\",\"requestOrigin\":\"https://review.spacedatanetwork.org\",\"reviewedTransform\":{\"metersPerSourceUnit\":1,\"rotation\":[0,0,0,1],\"scale\":[1,1,1],\"sourceUnits\":\"m\",\"translation\":[0,0,0],\"upAxis\":\"Y_UP\"},\"signatureProfile\":\"ed25519-over-sha256-jcs-v1\"}";
    assertCanonical(take(sign_asset_review_decision(
                        handle, approveRequest(), RegistryRowId::AssetReviewDecision)),
                    keyId, approveEnvelope,
                    "66d669400f9a2f61f9a017409a7ddd8a53f416bf71beb05f5f62d8202a587d18",
                    "4e7743ae7b605316faa819bf2f3b2afae9d22575f9d7187554476d8b3fb9052a0ab42f829696492a7dc1e147f30c8ad4c07142293ab61d4f2bff9abf3ccaeb0e");

    const std::string disapproveEnvelope =
        "{\"audience\":\"asset-review:assets.ipfs.01\",\"candidateKey\":\"asset-review:spacecraft/example:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"challengeId\":\"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\",\"clientId\":\"sdn-asset-review-v1\",\"decision\":\"disapprove\",\"expiresAt\":\"2026-07-21T00:05:00.000Z\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"issuedAt\":\"2026-07-21T00:00:00.000Z\",\"keyId\":\"sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d\",\"kind\":\"asset-review-attestation\",\"metadataSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"modelBytes\":12345,\"modelCid\":\"bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi\",\"modelSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"nonce\":\"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\",\"previousDecisionHead\":\"5bf299ed6cc14cefe075bad165cf1e02992903f976202e87772905385df87dda\",\"protocolVersion\":1,\"purpose\":\"asset-review-approval\",\"reason\":\"Synthetic fixture rejection.\",\"requestOrigin\":\"https://review.spacedatanetwork.org\",\"signatureProfile\":\"ed25519-over-sha256-jcs-v1\"}";
    assertCanonical(take(sign_asset_review_decision(
                        handle, disapproveRequest(), RegistryRowId::AssetReviewDecision)),
                    keyId, disapproveEnvelope,
                    "ec2a61462a1d560e1e4f7f8d17afb8a2857d6e12e3d0b63432dd65eedf614602",
                    "61f4bb58cfc76b54c6736f3922bbfef15342c9b9b197d16ded07725916ce02f192eedb301e54570ce1a0de1198241ebda05d481d00e307292c24507f176d6f02");
    destroy_identity(handle);
#endif
}

TEST_CASE(SdnSigning, ClosedOperationMatrixAndRegistryRowsCannotBeRelabeled) {
#if !HD_WALLET_FIPS_MODE
    const auto newHandle = deriveNew();
    const auto legacyHandle = deriveLegacy();
    const auto mnemonicHandle = deriveMnemonic();
    assertError(IdentityError::OperationNotAllowed,
                sign_sdn_login_v1(newHandle, sequence(0)));
    for (const IdentityHandle legacy : {legacyHandle, mnemonicHandle}) {
        assertError(IdentityError::OperationNotAllowed,
                    sign_sdn_login_v2(legacy, loginRequest(0),
                                      RegistryRowId::SdnNodeConsoleV2));
        assertError(IdentityError::OperationNotAllowed,
                    sign_asset_review_authority_activation(
                        legacy, activationRequest(),
                        RegistryRowId::AssetReviewAuthorityActivation));
        assertError(IdentityError::OperationNotAllowed,
                    sign_asset_review_decision(
                        legacy, approveRequest(),
                        RegistryRowId::AssetReviewDecision));
    }
    assertError(IdentityError::OperationNotAllowed,
                sign_sdn_login_v2(newHandle, loginRequest(0),
                                  RegistryRowId::AssetReviewDecision));
    auto wrongAudience = loginRequest(0);
    wrongAudience.audience = "sdn-login:evil.example";
    assertError(IdentityError::OperationNotAllowed,
                sign_sdn_login_v2(newHandle, wrongAudience,
                                  RegistryRowId::SdnNodeConsoleV2));
    auto wrongActivation = activationRequest();
    wrongActivation.client_id = "sdn-node-console-v1";
    assertError(IdentityError::OperationNotAllowed,
                sign_asset_review_authority_activation(
                    newHandle, wrongActivation,
                    RegistryRowId::AssetReviewAuthorityActivation));
    destroy_identity(newHandle);
    destroy_identity(legacyHandle);
    destroy_identity(mnemonicHandle);
#endif
}

TEST_CASE(SdnSigning, LoginAndActivationValidateEveryTypedFieldAndTimeBound) {
#if !HD_WALLET_FIPS_MODE
    const auto handle = deriveNew();
    const auto rejectLogin = [&](const SdnLoginV2Fields& request) {
        assertError(IdentityError::InvalidRequest,
                    sign_sdn_login_v2(handle, request,
                                      RegistryRowId::SdnNodeConsoleV2));
    };
    for (const uint32_t version : {0U, 1U, 3U}) {
        auto request = loginRequest(0);
        request.protocol_version = version;
        rejectLogin(request);
    }
    for (const std::string nonce : {
             std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'A'),
             std::string(64, 'g')}) {
        auto request = loginRequest(0);
        request.nonce = nonce;
        rejectLogin(request);
    }
    for (const std::string issued : {
             "0000-07-20T20:00:00.000Z", "2026-02-30T20:00:00.000Z",
             "2026-07-20 20:00:00.000Z", "2026-07-20T20:00:00Z"}) {
        auto request = loginRequest(0);
        request.issued_at = issued;
        rejectLogin(request);
    }
    for (const std::string expires : {
             "2026-07-20T20:00:00.000Z", "2026-07-20T19:59:59.999Z",
             "2026-07-20T20:05:00.001Z", "2026-07-20T20:05:00Z"}) {
        auto request = loginRequest(0);
        request.expires_at = expires;
        rejectLogin(request);
    }
    auto oneMillisecond = loginRequest(0);
    oneMillisecond.expires_at = "2026-07-20T20:00:00.001Z";
    ASSERT_TRUE(std::holds_alternative<CanonicalSignature>(sign_sdn_login_v2(
        handle, oneMillisecond, RegistryRowId::SdnNodeConsoleV2)));

    const auto rejectActivation = [&](const AuthorityActivationFields& request) {
        assertError(IdentityError::InvalidRequest,
                    sign_asset_review_authority_activation(
                        handle, request,
                        RegistryRowId::AssetReviewAuthorityActivation));
    };
    for (const auto mutate : {0, 1, 2, 3}) {
        auto request = activationRequest();
        if (mutate == 0) request.audience.push_back('x');
        if (mutate == 1) request.request_origin.push_back('/');
        if (mutate == 2) request.client_id.push_back('x');
        if (mutate == 3) request.service_instance.push_back('x');
        assertError(IdentityError::OperationNotAllowed,
                    sign_asset_review_authority_activation(
                        handle, request,
                        RegistryRowId::AssetReviewAuthorityActivation));
    }
    assertError(IdentityError::OperationNotAllowed,
                sign_asset_review_authority_activation(
                    handle, activationRequest(),
                    static_cast<RegistryRowId>(255)));
    for (const uint32_t version : {0U, 2U}) {
        auto request = activationRequest();
        request.protocol_version = version;
        rejectActivation(request);
    }
    auto activation = activationRequest();
    activation.purpose.push_back('x');
    rejectActivation(activation);
    for (const std::string nonce : {
             std::string(63, '0'), std::string(65, '0'), std::string(64, 'A'),
             std::string(64, 'g')}) {
        activation = activationRequest();
        activation.nonce = nonce;
        rejectActivation(activation);
    }
    for (const std::string expires : {
             "2026-07-20T22:00:00.000Z", "2026-07-20T22:05:00.001Z",
             "2026-07-20T22:05:00Z"}) {
        activation = activationRequest();
        activation.expires_at = expires;
        rejectActivation(activation);
    }
    activation = activationRequest();
    activation.public_key_hex[0] = 'A';
    rejectActivation(activation);
    activation = activationRequest();
    activation.public_key_hex.pop_back();
    rejectActivation(activation);
    activation = activationRequest();
    activation.key_id.push_back('0');
    rejectActivation(activation);
    activation = activationRequest();
    activation.identity_scheme = std::string(kLegacyFastIdentityScheme);
    rejectActivation(activation);
    activation = activationRequest();
    activation.signature_profile = "ed25519-raw-32-v1";
    rejectActivation(activation);
    destroy_identity(handle);
#endif
}

TEST_CASE(SdnSigning, DecisionIdentifiersCidGrammarAndAggregateBoundsAreClosed) {
#if !HD_WALLET_FIPS_MODE
    const auto handle = deriveNew();
    const auto reject = [&](const AssetReviewDecisionFields& request) {
        assertError(IdentityError::InvalidRequest,
                    sign_asset_review_decision(
                        handle, request, RegistryRowId::AssetReviewDecision));
    };
    const auto accept = [&](const AssetReviewDecisionFields& request) {
        ASSERT_TRUE(std::holds_alternative<CanonicalSignature>(
            sign_asset_review_decision(
                handle, request, RegistryRowId::AssetReviewDecision)));
    };

    for (const auto mutate : {0, 1, 2}) {
        auto request = approveRequest();
        if (mutate == 0) request.audience.push_back('x');
        if (mutate == 1) request.request_origin.push_back('/');
        if (mutate == 2) request.client_id.push_back('x');
        assertError(IdentityError::OperationNotAllowed,
                    sign_asset_review_decision(
                        handle, request, RegistryRowId::AssetReviewDecision));
    }
    assertError(IdentityError::OperationNotAllowed,
                sign_asset_review_decision(handle, approveRequest(),
                                           static_cast<RegistryRowId>(255)));

    auto request = approveRequest();
    request.protocol_version = 2;
    reject(request);
    for (const int field : {0, 1, 2, 3}) {
        for (const std::string invalid : {
                 std::string(63, 'a'), std::string(65, 'a'),
                 std::string(64, 'A'), std::string(64, 'g')}) {
            request = approveRequest();
            if (field == 0) request.challenge_id = invalid;
            if (field == 1) request.nonce = invalid;
            if (field == 2) request.model_sha256 = invalid;
            if (field == 3) request.metadata_sha256 = invalid;
            reject(request);
        }
    }
    request = approveRequest();
    request.previous_decision_head = std::string(63, 'a');
    reject(request);
    request = approveRequest();
    request.previous_decision_head = std::string(64, 'A');
    reject(request);
    request = approveRequest();
    request.previous_decision_head = std::string(64, 'a');
    accept(request);
    for (const std::string expires : {
             "2026-07-20T23:00:00.000Z", "2026-07-20T23:05:00.001Z",
             "2026-07-20T23:05:00Z"}) {
        request = approveRequest();
        request.expires_at = expires;
        reject(request);
    }

    request = approveRequest();
    request.model_bytes = 1;
    accept(request);
    request.model_bytes = 9007199254740991ULL;
    accept(request);
    request.model_bytes = 0;
    reject(request);
    request.model_bytes = 9007199254740992ULL;
    reject(request);

    for (const std::string invalid_cid : {
             std::string(""), std::string(58, 'a'), std::string(60, 'a'),
             rawSha256Cid(2, 0x55, 0x12, 0x20, 0xaa),
             rawSha256Cid(1, 0x54, 0x12, 0x20, 0xaa),
             rawSha256Cid(1, 0x55, 0x13, 0x20, 0xaa),
             rawSha256Cid(1, 0x55, 0x12, 0x1f, 0xaa),
             rawSha256Cid(1, 0x55, 0x12, 0x20, 0xbb)}) {
        request = approveRequest();
        request.model_cid = invalid_cid;
        reject(request);
    }
    request = approveRequest();
    request.model_cid[0] = 'B';
    reject(request);
    request = approveRequest();
    request.model_cid[1] = '0';
    reject(request);
    request = approveRequest();
    request.model_cid.back() = 'j'; // same decoded bytes, nonzero tail bits
    reject(request);

    request = approveRequest();
    request.candidate_key = "asset-review:a/a:" + request.model_sha256;
    accept(request);
    const std::string entity128 = "a/" + std::string(126, 'a');
    request = approveRequest();
    request.candidate_key =
        "asset-review:" + entity128 + ":" + request.model_sha256;
    ASSERT_EQ(size_t{206}, request.candidate_key.size());
    accept(request);
    for (const std::string entity : {
             std::string("a"), std::string("/a"), std::string("a/"),
             std::string("a/-a"), std::string("a/a/b"), std::string("A/a"),
             std::string("a/a_"), std::string("a/") + std::string(127, 'a')}) {
        request = approveRequest();
        request.candidate_key =
            "asset-review:" + entity + ":" + request.model_sha256;
        reject(request);
    }
    request = approveRequest();
    request.candidate_key.back() = 'b';
    reject(request);

    request = approveRequest();
    size_t fixed_string_bytes = request.audience.size() +
        request.request_origin.size() + request.client_id.size() +
        request.challenge_id.size() + request.nonce.size() +
        request.issued_at.size() + request.expires_at.size() +
        request.candidate_key.size() + request.model_cid.size() +
        request.model_sha256.size() + request.metadata_sha256.size() +
        request.note->size() + request.reviewed_transform->source_units.size();
    request.reviewed_transform->up_axis =
        std::string(16384 - fixed_string_bytes + 1, 'X');
    reject(request);
    destroy_identity(handle);
#endif
}

TEST_CASE(SdnSigning, TransformFixtureAndTextBoundsCoverEveryPublishedEdge) {
    const std::string fixture = readFixture("asset-review-v1.json");
    ASSERT_TRUE(fixture.find("\"quaternionNormTolerance\": 0.000001") !=
                std::string::npos);
    ASSERT_TRUE(fixture.find("\"min-positive-subnormal\"") !=
                std::string::npos);
    ASSERT_TRUE(fixture.find("\"above-positive-tolerance\"") !=
                std::string::npos);
    ASSERT_TRUE(fixture.find("\"unsupported-feet\"") != std::string::npos);
#if !HD_WALLET_FIPS_MODE
    const auto handle = deriveNew();
    const auto reject = [&](const AssetReviewDecisionFields& request) {
        assertError(IdentityError::InvalidRequest,
                    sign_asset_review_decision(
                        handle, request, RegistryRowId::AssetReviewDecision));
    };
    const auto accept = [&](const AssetReviewDecisionFields& request) {
        ASSERT_TRUE(std::holds_alternative<CanonicalSignature>(
            sign_asset_review_decision(
                handle, request, RegistryRowId::AssetReviewDecision)));
    };

    for (size_t axis = 0; axis < 3; ++axis) {
        for (const double value : {-1000000.0, 1000000.0}) {
            auto request = approveRequest();
            request.reviewed_transform->translation[axis] = value;
            accept(request);
        }
        for (const double value : {-1000000.0000000001,
                                   1000000.0000000001,
                                   std::numeric_limits<double>::infinity()}) {
            auto request = approveRequest();
            request.reviewed_transform->translation[axis] = value;
            reject(request);
        }
        for (const double value : {std::numeric_limits<double>::denorm_min(),
                                   1000000.0}) {
            auto request = approveRequest();
            request.reviewed_transform->scale[axis] = value;
            accept(request);
        }
        for (const double value : {-std::numeric_limits<double>::denorm_min(),
                                   0.0, 1000000.0000000001,
                                   std::numeric_limits<double>::infinity()}) {
            auto request = approveRequest();
            request.reviewed_transform->scale[axis] = value;
            reject(request);
        }
    }
    for (const double value : {0.9999990000000001, 1.000001}) {
        auto request = approveRequest();
        request.reviewed_transform->rotation = {0, 0, 0, value};
        accept(request);
    }
    for (const double value : {0.999999, 1.0000010000000001}) {
        auto request = approveRequest();
        request.reviewed_transform->rotation = {0, 0, 0, value};
        reject(request);
    }
    for (size_t component = 0; component < 4; ++component) {
        auto request = approveRequest();
        request.reviewed_transform->rotation[component] =
            std::numeric_limits<double>::quiet_NaN();
        reject(request);
    }
    auto request = approveRequest();
    request.reviewed_transform->rotation = {
        0.70710607407976633, 0.70710607407976633, 0, 0};
    accept(request);
    request = approveRequest();
    request.reviewed_transform->rotation = {
        0.70710748829332870, 0.70710748829332870, 0, 0};
    reject(request);

    for (const std::string axis : {"X_UP", "Y_UP", "Z_UP"}) {
        request = approveRequest();
        request.reviewed_transform->up_axis = axis;
        accept(request);
    }
    request = approveRequest();
    request.reviewed_transform->up_axis = "W_UP";
    reject(request);
    struct UnitPair { const char* unit; double meters; };
    for (const UnitPair pair : {UnitPair{"m", 1}, UnitPair{"cm", 0.01},
                                UnitPair{"mm", 0.001}, UnitPair{"km", 1000}}) {
        request = approveRequest();
        request.reviewed_transform->source_units = pair.unit;
        request.reviewed_transform->meters_per_source_unit = pair.meters;
        accept(request);
    }
    for (const UnitPair pair : {UnitPair{"m", 0.01}, UnitPair{"ft", 0.3048}}) {
        request = approveRequest();
        request.reviewed_transform->source_units = pair.unit;
        request.reviewed_transform->meters_per_source_unit = pair.meters;
        reject(request);
    }
    request = approveRequest();
    request.reviewed_transform->meters_per_source_unit =
        std::numeric_limits<double>::quiet_NaN();
    reject(request);

    request = approveRequest();
    request.note.reset();
    accept(request);
    request = approveRequest();
    request.note = "";
    reject(request);
    request = approveRequest();
    request.note = std::string(2000, 'x');
    accept(request);
    request.note = std::string(2001, 'x');
    reject(request);
    request = approveRequest();
    request.reason = "forbidden";
    reject(request);
    request = approveRequest();
    request.reviewed_transform.reset();
    reject(request);

    auto disapprove = disapproveRequest();
    disapprove.reason = std::string(2000, 'x');
    accept(disapprove);
    disapprove.reason = std::string(2001, 'x');
    reject(disapprove);
    disapprove = disapproveRequest();
    disapprove.reviewed_transform = identityTransform();
    reject(disapprove);
    disapprove = disapproveRequest();
    disapprove.note = "forbidden";
    reject(disapprove);
    disapprove = disapproveRequest();
    disapprove.reason.reset();
    reject(disapprove);
    disapprove = disapproveRequest();
    disapprove.decision = static_cast<ReviewDecision>(99);
    reject(disapprove);

    const std::array<uint32_t, 25> trim_scalars = {
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x00a0, 0x1680, 0x2000,
        0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
        0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
    };
    for (const uint32_t scalar : trim_scalars) {
        const std::string whitespace = utf8(scalar);
        for (const std::string text : {whitespace + "x", "x" + whitespace}) {
            request = approveRequest();
            request.note = text;
            reject(request);
            disapprove = disapproveRequest();
            disapprove.reason = text;
            reject(disapprove);
        }
        request = approveRequest();
        request.note = "x" + whitespace + "x";
        accept(request);
    }
    request = approveRequest();
    request.note = std::string("bad\xc0\xaf", 5);
    reject(request);
    disapprove = disapproveRequest();
    disapprove.reason = "x" + utf8(0xfdd0);
    reject(disapprove);
    destroy_identity(handle);
#endif
}

TEST_CASE(SdnSigning, CanonicalJsonImplementsRfc8785AndRejectsAmbiguity) {
    using namespace hd_wallet::sdn::jcs;
    const Limits limits{};
    auto parsed = parse_json(bytes(std::string(
        "{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"
        "\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\",\"literals\":[null,true,false]}")),
        limits);
    ASSERT_TRUE(std::holds_alternative<Value>(parsed));
    ASSERT_STR_EQ(
        "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\"}",
        serialize(std::get<Value>(parsed)));

    struct OfficialNumber {
        uint64_t ieee754;
        const char* json;
    };
    const OfficialNumber appendixB[] = {
        {0x0000000000000000ULL, "0"},
        {0x8000000000000000ULL, "0"},
        {0x0000000000000001ULL, "5e-324"},
        {0x8000000000000001ULL, "-5e-324"},
        {0x7fefffffffffffffULL, "1.7976931348623157e+308"},
        {0xffefffffffffffffULL, "-1.7976931348623157e+308"},
        {0x4340000000000000ULL, "9007199254740992"},
        {0xc340000000000000ULL, "-9007199254740992"},
        {0x4430000000000000ULL, "295147905179352830000"},
        {0x44b52d02c7e14af5ULL, "9.999999999999997e+22"},
        {0x44b52d02c7e14af6ULL, "1e+23"},
        {0x44b52d02c7e14af7ULL, "1.0000000000000001e+23"},
        {0x444b1ae4d6e2ef4eULL, "999999999999999700000"},
        {0x444b1ae4d6e2ef4fULL, "999999999999999900000"},
        {0x444b1ae4d6e2ef50ULL, "1e+21"},
        {0x3eb0c6f7a0b5ed8cULL, "9.999999999999997e-7"},
        {0x3eb0c6f7a0b5ed8dULL, "0.000001"},
        {0x41b3de4355555553ULL, "333333333.3333332"},
        {0x41b3de4355555554ULL, "333333333.33333325"},
        {0x41b3de4355555555ULL, "333333333.3333333"},
        {0x41b3de4355555556ULL, "333333333.3333334"},
        {0x41b3de4355555557ULL, "333333333.33333343"},
        {0xbecbf647612f3696ULL, "-0.0000033333333333333333"},
        {0x43143ff3c1cb0959ULL, "1424953923781206.2"},
    };
    for (const auto& row : appendixB) {
        ASSERT_STR_EQ(row.json,
                      serialize(Value(std::bit_cast<double>(row.ieee754))));
    }

    Value::Members numbers;
    numbers.emplace_back("negativeZero", Value(-0.0));
    numbers.emplace_back("min", Value(std::numeric_limits<double>::denorm_min()));
    numbers.emplace_back("decimalLow", Value(1e-6));
    numbers.emplace_back("exponentLow", Value(1e-7));
    numbers.emplace_back("decimalHigh", Value(1e20));
    numbers.emplace_back("exponentHigh", Value(1e21));
    ASSERT_STR_EQ(
        "{\"decimalHigh\":100000000000000000000,\"decimalLow\":0.000001,\"exponentHigh\":1e+21,\"exponentLow\":1e-7,\"min\":5e-324,\"negativeZero\":0}",
        serialize(Value(std::move(numbers))));

    Value::Members utf16Order;
    utf16Order.emplace_back("\xef\xac\x83", Value(1.0));
    utf16Order.emplace_back("\xf0\x9f\x98\x80", Value(2.0));
    utf16Order.emplace_back("\xef\xbf\xbd", Value(3.0));
    ASSERT_STR_EQ("{\"😀\":2,\"ﬃ\":1,\"�\":3}", serialize(Value(std::move(utf16Order))));

    Value::Members officialKeyOrder;
    officialKeyOrder.emplace_back("€", Value("Euro Sign"));
    officialKeyOrder.emplace_back("\r", Value("Carriage Return"));
    officialKeyOrder.emplace_back("דּ", Value("Hebrew Letter Dalet With Dagesh"));
    officialKeyOrder.emplace_back("1", Value("One"));
    officialKeyOrder.emplace_back("😀", Value("Emoji: Grinning Face"));
    officialKeyOrder.emplace_back("\xc2\x80", Value("Control"));
    officialKeyOrder.emplace_back("ö", Value("Latin Small Letter O With Diaeresis"));
    ASSERT_STR_EQ(
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}",
        serialize(Value(std::move(officialKeyOrder))));

    assertJcsError(JcsError::DuplicateKey,
                   parse_json(bytes(std::string("{\"a\":1,\"a\":2}")), limits));
    assertJcsError(
        JcsError::DuplicateKey,
        parse_json(bytes(std::string("{\"outer\":{\"a\":1,\"a\":2}}")),
                   limits));
    assertJcsError(JcsError::TrailingData,
                   parse_json(bytes(std::string("null true")), limits));
    assertJcsError(
        JcsError::InvalidSyntax,
        parse_json(std::span<const uint8_t>(
                       reinterpret_cast<const uint8_t*>("\xef\xbb\xbf{}"), 5),
                   limits));
    assertJcsError(JcsError::InvalidUtf8,
                   parse_json(std::span<const uint8_t>(
                       reinterpret_cast<const uint8_t*>("\xc0\xaf"), 2), limits));
    assertJcsError(JcsError::InvalidString,
                   parse_json(bytes(std::string("\"\\x\"")), limits));
    assertJcsError(JcsError::Noncharacter,
                   parse_json(bytes(std::string("\"\xef\xb7\x90\"")), limits));
    assertJcsError(JcsError::Noncharacter,
                   parse_json(bytes(std::string("\"\\udbff\\udfff\"")), limits));
    size_t noncharacters = 0;
    for (uint32_t scalar = 0xfdd0; scalar <= 0xfdef; ++scalar) {
        assertJcsError(JcsError::Noncharacter,
                       parse_json(bytes(std::string("\"") + utf8(scalar) + "\""),
                                  limits));
        ++noncharacters;
    }
    for (uint32_t plane = 0; plane <= 16; ++plane) {
        for (const uint32_t tail : {0xfffeU, 0xffffU}) {
            const uint32_t scalar = (plane << 16) | tail;
            assertJcsError(
                JcsError::Noncharacter,
                parse_json(bytes(std::string("\"") + utf8(scalar) + "\""), limits));
            ++noncharacters;
        }
    }
    ASSERT_EQ(size_t{66}, noncharacters);
    assertJcsError(JcsError::InvalidString,
                   parse_json(bytes(std::string("\"\\ud800\"")), limits));
    assertJcsError(JcsError::InvalidNumber,
                   parse_json(bytes(std::string("1e9999")), limits));
    for (const std::string invalid : {"01", "1.", ".1", "+1", "--1", "1e"}) {
        assertJcsError(JcsError::InvalidNumber, parse_json(bytes(invalid), limits));
    }
    assertJcsError(JcsError::NonFiniteNumber,
                   serialize_jcs(Value(std::numeric_limits<double>::infinity()), limits));
    assertJcsError(JcsError::NonFiniteNumber,
                   serialize_jcs(Value(std::numeric_limits<double>::quiet_NaN()),
                                 limits));
    assertJcsError(JcsError::NotCanonical,
                   parse_exact_jcs(bytes(std::string("{ \"a\" : 1 }")), limits));

    Limits tiny = limits;
    tiny.max_depth = 2;
    assertJcsError(JcsError::DepthLimit,
                   parse_json(bytes(std::string("[[[]]]")), tiny));
    tiny = limits;
    tiny.max_tokens = 2;
    assertJcsError(JcsError::TokenLimit,
                   parse_json(bytes(std::string("[1,2,3]")), tiny));
    tiny = limits;
    tiny.max_string_bytes = 2;
    assertJcsError(JcsError::StringLimit,
                   parse_json(bytes(std::string("\"abc\"")), tiny));
    tiny = limits;
    tiny.max_bytes = 3;
    assertJcsError(JcsError::ByteLimit,
                   parse_json(bytes(std::string("null")), tiny));
}

TEST_CASE(SdnSigning, HkdfAndAesGcmMatchIndependentPrimitiveKnownAnswers) {
#if HD_WALLET_SDN_IDENTITY_TESTING
    using namespace hd_wallet::sdn::internal;
    const auto ikm = test::hexToBytes(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = test::hexToBytes("000102030405060708090a0b0c");
    const auto info = test::hexToBytes("f0f1f2f3f4f5f6f7f8f9");
    ASSERT_STR_EQ(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        test::bytesToHex(take(testing_hkdf_sha256(bytes(ikm), bytes(salt), bytes(info), 42))));

    const auto key = test::hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000000");
    const auto nonce = test::hexToBytes("000000000000000000000000");
    const auto plaintext = test::hexToBytes("00000000000000000000000000000000");
    const std::vector<uint8_t> aad;
    const auto sealed = take(testing_aes256_gcm_seal(
        bytes(key), bytes(nonce), bytes(plaintext), bytes(aad)));
    ASSERT_STR_EQ("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
                  test::bytesToHex(sealed));
    ASSERT_STR_EQ("00000000000000000000000000000000",
                  test::bytesToHex(take(testing_aes256_gcm_open(
                      bytes(key), bytes(nonce), bytes(sealed), bytes(aad)))));
#endif
}
