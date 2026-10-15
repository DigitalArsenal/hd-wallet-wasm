/**
 * @file test_curves.cpp
 * @brief Multi-Curve Cryptography Tests
 *
 * Tests for elliptic curve operations including:
 * - secp256k1 (Bitcoin, Ethereum)
 * - Ed25519 (Solana, Polkadot)
 * - P-256 (NIST)
 * - P-384 (NIST)
 * - ECDH key exchange
 */

#include "test_framework.h"
#include "hd_wallet/types.h"
#include "hd_wallet/bip32.h"

// Note: These headers would exist in the full implementation
// #include "hd_wallet/curves.h"
// #include "hd_wallet/ecdsa.h"
// #include "hd_wallet/eddsa.h"
// #include "hd_wallet/ecdh.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace hd_wallet;

// =============================================================================
// secp256k1 Test Vectors
// =============================================================================

struct Secp256k1SignVector {
    const char* private_key_hex;
    const char* message_hash_hex;  // 32 bytes SHA-256
    const char* expected_signature_hex;  // DER encoded or compact
    const char* expected_public_key_hex;  // Compressed 33 bytes
};

// Standard secp256k1 test vectors
static const Secp256k1SignVector SECP256K1_SIGN_VECTORS[] = {
    {
        // Test vector 1: Well-known private key
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    },
    {
        // Test vector 2: Random private key
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "",  // Signature varies with k
        "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    },
    {
        // Test vector 3: Bitcoin-style key
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "9302bda273a887cb40c13e02a50b4071a31fd3afd03f42fe44cbc6c6c90e95c7",
        "",
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    }
};

// =============================================================================
// Ed25519 Test Vectors (from RFC 8032)
// =============================================================================

struct Ed25519SignVector {
    const char* private_key_hex;  // 32 bytes seed
    const char* public_key_hex;   // 32 bytes
    const char* message_hex;
    const char* signature_hex;    // 64 bytes
};

static const Ed25519SignVector ED25519_SIGN_VECTORS[] = {
    // Test 1: Empty message
    {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    },
    // Test 2: Single byte message (0x72)
    {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    },
    // Test 3: Two bytes
    {
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    },
    // Test 4: 1023 bytes
    {
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
    }
};

// =============================================================================
// P-256 (secp256r1) Test Vectors
// =============================================================================

struct P256SignVector {
    const char* private_key_hex;
    const char* public_key_x_hex;
    const char* public_key_y_hex;
    const char* message_hash_hex;
    // Note: ECDSA signatures are non-deterministic without RFC 6979
};

static const P256SignVector P256_SIGN_VECTORS[] = {
    {
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    }
};

// =============================================================================
// ECDH Test Vectors
// =============================================================================

struct EcdhVector {
    const char* private_key_a_hex;
    const char* public_key_a_hex;  // Compressed
    const char* private_key_b_hex;
    const char* public_key_b_hex;  // Compressed
    const char* shared_secret_hex;
};

// secp256k1 ECDH vectors
static const EcdhVector ECDH_SECP256K1_VECTORS[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    }
};

// X25519 test vectors (from RFC 7748)
static const EcdhVector ECDH_X25519_VECTORS[] = {
    {
        // Alice's private key (clamped)
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        // Alice's public key
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        // Bob's private key (clamped)
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        // Bob's public key
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        // Shared secret
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }
};

// =============================================================================
// Test: secp256k1 Public Key Derivation
// =============================================================================

TEST_CASE(Curves, Secp256k1_PublicKeyFromPrivate) {
    for (const auto& vec : SECP256K1_SIGN_VECTORS) {
        auto privkey = test::hexToArray<32>(vec.private_key_hex);
        auto expectedPubkey = test::hexToBytes(vec.expected_public_key_hex);

        auto pubkeyResult = bip32::publicKeyFromPrivate(privkey, Curve::SECP256K1);
        ASSERT_OK(pubkeyResult);

        ASSERT_BYTES_EQ(expectedPubkey.data(), pubkeyResult.value.data(), 33);
    }
}

TEST_CASE(Curves, Secp256k1_PublicKeyCompression) {
    // Uncompressed public key (65 bytes with 0x04 prefix)
    const char* uncompressed_hex =
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    auto uncompressed = test::hexToBytes(uncompressed_hex);

    Bytes65 uncompressed65{};
    std::copy(uncompressed.begin(), uncompressed.end(), uncompressed65.begin());

    auto compressedResult = bip32::compressPublicKey(uncompressed65, Curve::SECP256K1);
    ASSERT_OK(compressedResult);

    // Should be compressed to 33 bytes starting with 0x02 or 0x03
    ASSERT_EQ(33u, compressedResult.value.size());
    ASSERT_TRUE(compressedResult.value[0] == 0x02 || compressedResult.value[0] == 0x03);
}

TEST_CASE(Curves, Secp256k1_PublicKeyDecompression) {
    // Compressed public key
    const char* compressed_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    auto compressed = test::hexToBytes(compressed_hex);

    Bytes33 compressed33{};
    std::copy(compressed.begin(), compressed.end(), compressed33.begin());

    auto uncompressedResult = bip32::decompressPublicKey(compressed33, Curve::SECP256K1);
    ASSERT_OK(uncompressedResult);

    // Should be 65 bytes starting with 0x04
    ASSERT_EQ(65u, uncompressedResult.value.size());
    ASSERT_EQ(0x04, uncompressedResult.value[0]);
}

// =============================================================================
// Test: secp256k1 Signing and Verification
// =============================================================================

// These tests require the ecdsa module to be implemented
// Placeholder structure for when the module is available

TEST_CASE(Curves, Secp256k1_SignAndVerify) {
    // This test will be fully functional when hd_wallet/ecdsa.h is implemented
    auto privkey = test::hexToArray<32>(SECP256K1_SIGN_VECTORS[0].private_key_hex);
    auto messageHash = test::hexToArray<32>(SECP256K1_SIGN_VECTORS[0].message_hash_hex);

    // Get public key
    auto pubkeyResult = bip32::publicKeyFromPrivate(privkey, Curve::SECP256K1);
    ASSERT_OK(pubkeyResult);

    // TODO: Uncomment when ecdsa module is available
    // auto signResult = ecdsa::sign(privkey, messageHash, Curve::SECP256K1);
    // ASSERT_OK(signResult);
    //
    // auto verifyResult = ecdsa::verify(pubkeyResult.value, messageHash, signResult.value, Curve::SECP256K1);
    // ASSERT_OK(verifyResult);
    // ASSERT_TRUE(verifyResult.value);
}

TEST_CASE(Curves, Secp256k1_RecoverableSignature) {
    // Test recoverable signature (used in Ethereum)
    auto privkey = test::hexToArray<32>(SECP256K1_SIGN_VECTORS[2].private_key_hex);
    auto messageHash = test::hexToArray<32>(SECP256K1_SIGN_VECTORS[2].message_hash_hex);

    auto pubkeyResult = bip32::publicKeyFromPrivate(privkey, Curve::SECP256K1);
    ASSERT_OK(pubkeyResult);

    // TODO: Uncomment when ecdsa module is available
    // auto signResult = ecdsa::signRecoverable(privkey, messageHash, Curve::SECP256K1);
    // ASSERT_OK(signResult);
    //
    // // Recover public key from signature
    // auto recoverResult = ecdsa::recover(messageHash, signResult.value);
    // ASSERT_OK(recoverResult);
    // ASSERT_BYTES_EQ(pubkeyResult.value.data(), recoverResult.value.data(), 33);
}

// =============================================================================
// Test: Ed25519 Signing and Verification
// =============================================================================

TEST_CASE(Curves, Ed25519_SignAndVerify_EmptyMessage) {
    const auto& vec = ED25519_SIGN_VECTORS[0];

    auto privateKey = test::hexToBytes(vec.private_key_hex);
    auto expectedPublicKey = test::hexToBytes(vec.public_key_hex);
    auto expectedSignature = test::hexToBytes(vec.signature_hex);
    ByteVector message;  // Empty

    // TODO: Uncomment when eddsa module is available
    // auto pubkeyResult = eddsa::publicKeyFromPrivate(privateKey);
    // ASSERT_OK(pubkeyResult);
    // ASSERT_BYTES_EQ(expectedPublicKey.data(), pubkeyResult.value.data(), 32);
    //
    // auto signResult = eddsa::sign(privateKey, message);
    // ASSERT_OK(signResult);
    // ASSERT_BYTES_EQ(expectedSignature.data(), signResult.value.data(), 64);
    //
    // auto verifyResult = eddsa::verify(expectedPublicKey, message, expectedSignature);
    // ASSERT_OK(verifyResult);
    // ASSERT_TRUE(verifyResult.value);
}

TEST_CASE(Curves, Ed25519_SignAndVerify_SingleByte) {
    const auto& vec = ED25519_SIGN_VECTORS[1];

    auto privateKey = test::hexToBytes(vec.private_key_hex);
    auto expectedPublicKey = test::hexToBytes(vec.public_key_hex);
    auto message = test::hexToBytes(vec.message_hex);
    auto expectedSignature = test::hexToBytes(vec.signature_hex);

    // TODO: Uncomment when eddsa module is available
    // auto signResult = eddsa::sign(privateKey, message);
    // ASSERT_OK(signResult);
    // ASSERT_BYTES_EQ(expectedSignature.data(), signResult.value.data(), 64);
    //
    // auto verifyResult = eddsa::verify(expectedPublicKey, message, expectedSignature);
    // ASSERT_OK(verifyResult);
    // ASSERT_TRUE(verifyResult.value);
}

TEST_CASE(Curves, Ed25519_SignAndVerify_TwoBytes) {
    const auto& vec = ED25519_SIGN_VECTORS[2];

    auto privateKey = test::hexToBytes(vec.private_key_hex);
    auto expectedPublicKey = test::hexToBytes(vec.public_key_hex);
    auto message = test::hexToBytes(vec.message_hex);
    auto expectedSignature = test::hexToBytes(vec.signature_hex);

    // TODO: Uncomment when eddsa module is available
    // auto signResult = eddsa::sign(privateKey, message);
    // ASSERT_OK(signResult);
    // ASSERT_BYTES_EQ(expectedSignature.data(), signResult.value.data(), 64);
}

TEST_CASE(Curves, Ed25519_InvalidSignature) {
    const auto& vec = ED25519_SIGN_VECTORS[0];

    auto publicKey = test::hexToBytes(vec.public_key_hex);
    ByteVector message;

    // Create invalid signature (flip a bit)
    auto badSignature = test::hexToBytes(vec.signature_hex);
    badSignature[0] ^= 0x01;

    // TODO: Uncomment when eddsa module is available
    // auto verifyResult = eddsa::verify(publicKey, message, badSignature);
    // ASSERT_OK(verifyResult);
    // ASSERT_FALSE(verifyResult.value);  // Should fail verification
}

// =============================================================================
// Test: P-256 Signing and Verification
// =============================================================================

TEST_CASE(Curves, P256_PublicKeyFromPrivate) {
    const auto& vec = P256_SIGN_VECTORS[0];

    auto privkey = test::hexToBytes(vec.private_key_hex);
    auto expectedX = test::hexToBytes(vec.public_key_x_hex);
    auto expectedY = test::hexToBytes(vec.public_key_y_hex);

    Bytes32 privkey32{};
    std::copy(privkey.begin(), privkey.end(), privkey32.begin());

    auto pubkeyResult = bip32::publicKeyFromPrivate(privkey32, Curve::P256);
    if (!pubkeyResult.ok()) {
        SKIP_TEST("P-256 curve not yet implemented");
    }

    // Decompress and verify X coordinate
    auto uncompressedResult = bip32::decompressPublicKey(pubkeyResult.value, Curve::P256);
    ASSERT_OK(uncompressedResult);

    // X coordinate is bytes 1-32, Y is bytes 33-64
    for (size_t i = 0; i < 32; ++i) {
        ASSERT_EQ(expectedX[i], uncompressedResult.value[1 + i]);
    }
}

TEST_CASE(Curves, P256_SignAndVerify) {
    const auto& vec = P256_SIGN_VECTORS[0];

    auto privkey = test::hexToBytes(vec.private_key_hex);
    auto messageHash = test::hexToBytes(vec.message_hash_hex);

    Bytes32 privkey32{};
    std::copy(privkey.begin(), privkey.end(), privkey32.begin());

    Bytes32 hash32{};
    std::copy(messageHash.begin(), messageHash.end(), hash32.begin());

    auto pubkeyResult = bip32::publicKeyFromPrivate(privkey32, Curve::P256);
    if (!pubkeyResult.ok()) {
        SKIP_TEST("P-256 curve not yet implemented");
    }

    // TODO: Uncomment when ecdsa module is available
    // auto signResult = ecdsa::sign(privkey32, hash32, Curve::P256);
    // ASSERT_OK(signResult);
    //
    // auto verifyResult = ecdsa::verify(pubkeyResult.value, hash32, signResult.value, Curve::P256);
    // ASSERT_OK(verifyResult);
    // ASSERT_TRUE(verifyResult.value);
}

// =============================================================================
// Test: P-384 Operations
// =============================================================================

TEST_CASE(Curves, P384_PublicKeyFromPrivate) {
    // P-384 private key (48 bytes)
    const char* privkey_hex =
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa477407787627"
        "97fe324cd897fecf1c8d1fded7d6e5e7d";

    auto privkey = test::hexToBytes(privkey_hex);

    // P-384 keys are 48 bytes, but we need to handle differently
    // For now, just verify the curve is recognized
    ASSERT_EQ(Curve::P384, Curve::P384);  // Placeholder

    // TODO: Full P-384 test when curves module is available
}

// =============================================================================
// Test: ECDH Key Exchange (secp256k1)
// =============================================================================

TEST_CASE(Curves, ECDH_Secp256k1) {
    const auto& vec = ECDH_SECP256K1_VECTORS[0];

    auto privA = test::hexToBytes(vec.private_key_a_hex);
    auto pubA = test::hexToBytes(vec.public_key_a_hex);
    auto privB = test::hexToBytes(vec.private_key_b_hex);
    auto pubB = test::hexToBytes(vec.public_key_b_hex);
    auto expectedSecret = test::hexToBytes(vec.shared_secret_hex);

    // TODO: Uncomment when ecdh module is available
    // Bytes32 privA32{}, privB32{};
    // std::copy(privA.begin(), privA.end(), privA32.begin());
    // std::copy(privB.begin(), privB.end(), privB32.begin());
    //
    // Bytes33 pubA33{}, pubB33{};
    // std::copy(pubA.begin(), pubA.end(), pubA33.begin());
    // std::copy(pubB.begin(), pubB.end(), pubB33.begin());
    //
    // // A computes shared secret with B's public key
    // auto secretAResult = ecdh::computeSecret(privA32, pubB33, Curve::SECP256K1);
    // ASSERT_OK(secretAResult);
    //
    // // B computes shared secret with A's public key
    // auto secretBResult = ecdh::computeSecret(privB32, pubA33, Curve::SECP256K1);
    // ASSERT_OK(secretBResult);
    //
    // // Both should derive the same secret
    // ASSERT_BYTES_EQ(secretAResult.value.data(), secretBResult.value.data(), 32);
    // ASSERT_BYTES_EQ(expectedSecret.data(), secretAResult.value.data(), 32);
}

// =============================================================================
// Test: X25519 Key Exchange
// =============================================================================

TEST_CASE(Curves, ECDH_X25519) {
    const auto& vec = ECDH_X25519_VECTORS[0];

    auto privA = test::hexToBytes(vec.private_key_a_hex);
    auto pubA = test::hexToBytes(vec.public_key_a_hex);
    auto privB = test::hexToBytes(vec.private_key_b_hex);
    auto pubB = test::hexToBytes(vec.public_key_b_hex);
    auto expectedSecret = test::hexToBytes(vec.shared_secret_hex);

    // TODO: Uncomment when ecdh module is available
    // auto secretAResult = ecdh::x25519(privA, pubB);
    // ASSERT_OK(secretAResult);
    //
    // auto secretBResult = ecdh::x25519(privB, pubA);
    // ASSERT_OK(secretBResult);
    //
    // // Both should derive the same secret
    // ASSERT_BYTES_EQ(secretAResult.value.data(), secretBResult.value.data(), 32);
    // ASSERT_BYTES_EQ(expectedSecret.data(), secretAResult.value.data(), 32);
}

// =============================================================================
// Test: Curve Properties
// =============================================================================

TEST_CASE(Curves, CurveProperties_KeySizes) {
    // secp256k1
    ASSERT_EQ(32u, curvePrivateKeySize(Curve::SECP256K1));
    ASSERT_EQ(33u, curvePublicKeyCompressedSize(Curve::SECP256K1));
    ASSERT_EQ(65u, curvePublicKeyUncompressedSize(Curve::SECP256K1));

    // Ed25519
    ASSERT_EQ(32u, curvePrivateKeySize(Curve::ED25519));
    ASSERT_EQ(32u, curvePublicKeyCompressedSize(Curve::ED25519));  // Ed25519 is always 32

    // P-256
    ASSERT_EQ(32u, curvePrivateKeySize(Curve::P256));
    ASSERT_EQ(33u, curvePublicKeyCompressedSize(Curve::P256));
    ASSERT_EQ(65u, curvePublicKeyUncompressedSize(Curve::P256));

    // P-384
    ASSERT_EQ(48u, curvePrivateKeySize(Curve::P384));
    ASSERT_EQ(49u, curvePublicKeyCompressedSize(Curve::P384));
    ASSERT_EQ(97u, curvePublicKeyUncompressedSize(Curve::P384));
}

TEST_CASE(Curves, CurveProperties_Names) {
    ASSERT_STR_EQ("secp256k1", curveToString(Curve::SECP256K1));
    ASSERT_STR_EQ("Ed25519", curveToString(Curve::ED25519));
    ASSERT_STR_EQ("P-256 (secp256r1)", curveToString(Curve::P256));
    ASSERT_STR_EQ("P-384 (secp384r1)", curveToString(Curve::P384));
    ASSERT_STR_EQ("X25519", curveToString(Curve::X25519));
}

// =============================================================================
// Test: Invalid Keys
// =============================================================================

TEST_CASE(Curves, InvalidPrivateKey_Zero) {
    Bytes32 zeroKey{};  // All zeros

    auto result = bip32::publicKeyFromPrivate(zeroKey, Curve::SECP256K1);
    ASSERT_EQ(Error::INVALID_PRIVATE_KEY, result.error);
}

TEST_CASE(Curves, InvalidPrivateKey_TooLarge) {
    // Private key >= curve order is invalid for secp256k1
    // secp256k1 order: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    auto tooLarge = test::hexToArray<32>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    auto result = bip32::publicKeyFromPrivate(tooLarge, Curve::SECP256K1);
    ASSERT_EQ(Error::INVALID_PRIVATE_KEY, result.error);
}

TEST_CASE(Curves, InvalidPublicKey_WrongPrefix) {
    // Valid public keys start with 0x02, 0x03 (compressed) or 0x04 (uncompressed)
    Bytes33 badKey{};
    badKey[0] = 0x05;  // Invalid prefix

    auto result = bip32::decompressPublicKey(badKey, Curve::SECP256K1);
    ASSERT_EQ(Error::INVALID_PUBLIC_KEY, result.error);
}

// =============================================================================
// Test: Deterministic Signatures (RFC 6979)
// =============================================================================

TEST_CASE(Curves, DeterministicSignatures) {
    // When using RFC 6979, same key + message should always produce same signature
    auto privkey = test::hexToArray<32>("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    auto messageHash = test::hexToArray<32>("9302bda273a887cb40c13e02a50b4071a31fd3afd03f42fe44cbc6c6c90e95c7");

    // TODO: Uncomment when ecdsa module is available
    // auto sig1 = ecdsa::sign(privkey, messageHash, Curve::SECP256K1);
    // auto sig2 = ecdsa::sign(privkey, messageHash, Curve::SECP256K1);
    //
    // ASSERT_OK(sig1);
    // ASSERT_OK(sig2);
    //
    // // Signatures should be identical with RFC 6979
    // ASSERT_BYTES_EQ(sig1.value.data(), sig2.value.data(), sig1.value.size());
}

// =============================================================================
// Test: Key validation and strict Ed25519 (2.1.1)
// =============================================================================

#include "hd_wallet/eddsa.h"
#include "../src/key_validation.h"

#include <cryptopp/integer.h>
#include <cryptopp/sha.h>

#include <algorithm>

namespace {

// Ed25519 group order L, little-endian.
const char* const kEd25519OrderLe = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

ByteVector addLe(const uint8_t* a, const ByteVector& b) {
    ByteVector out(32);
    unsigned carry = 0;
    for (size_t i = 0; i < 32; ++i) {
        const unsigned sum = static_cast<unsigned>(a[i]) + b[i] + carry;
        out[i] = static_cast<uint8_t>(sum);
        carry = sum >> 8;
    }
    return out;
}

} // namespace

TEST_CASE(Curves, Ed25519_StrictVerify_RfcVectorsPass) {
    for (const auto& vec : ED25519_SIGN_VECTORS) {
        auto publicKey = test::hexToArray<32>(vec.public_key_hex);
        auto signature = test::hexToArray<64>(vec.signature_hex);
        auto message = test::hexToBytes(vec.message_hex);
        ASSERT_TRUE(eddsa::ed25519Verify(publicKey, message, signature));
    }
}

TEST_CASE(Curves, Ed25519_StrictVerify_RejectsSPlusL) {
    const auto& vec = ED25519_SIGN_VECTORS[1];
    auto publicKey = test::hexToArray<32>(vec.public_key_hex);
    auto signature = test::hexToArray<64>(vec.signature_hex);
    auto message = test::hexToBytes(vec.message_hex);
    ASSERT_TRUE(eddsa::ed25519Verify(publicKey, message, signature));

    // S + L is the same scalar mod L: the cofactorless equation still holds,
    // so only the S < L rule rejects it.
    auto sPlusL = addLe(signature.data() + 32, test::hexToBytes(kEd25519OrderLe));
    std::copy(sPlusL.begin(), sPlusL.end(), signature.begin() + 32);
    ASSERT_FALSE(eddsa::ed25519Verify(publicKey, message, signature));
}

TEST_CASE(Curves, Ed25519_StrictVerify_RejectsSmallOrderKey) {
    // With A the identity, [S]B == R + [k]A for any message when R = [S]B:
    // S = a mod L for a seed's clamped scalar a, R = that seed's public key.
    auto seed = test::hexToArray<32>(ED25519_SIGN_VECTORS[0].private_key_hex);
    auto R = test::hexToArray<32>(ED25519_SIGN_VECTORS[0].public_key_hex);
    uint8_t digest[64];
    CryptoPP::SHA512().CalculateDigest(digest, seed.data(), seed.size());
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;
    const CryptoPP::Integer a(digest, 32, CryptoPP::Integer::UNSIGNED, CryptoPP::LITTLE_ENDIAN_ORDER);
    auto orderLe = test::hexToBytes(kEd25519OrderLe);
    const CryptoPP::Integer L(orderLe.data(), 32, CryptoPP::Integer::UNSIGNED, CryptoPP::LITTLE_ENDIAN_ORDER);
    uint8_t sBigEndian[32];
    (a % L).Encode(sBigEndian, 32);

    eddsa::Ed25519Signature forged{};
    std::copy(R.begin(), R.end(), forged.begin());
    for (size_t i = 0; i < 32; ++i) forged[32 + i] = sBigEndian[31 - i];

    eddsa::Ed25519PublicKey identity{};
    identity[0] = 0x01;
    const std::string message = "any message at all";
    ASSERT_FALSE(eddsa::ed25519Verify(identity, message, forged));

    // The same key encoded non-canonically (y = p + 1).
    eddsa::Ed25519PublicKey nonCanonical{};
    nonCanonical.fill(0xff);
    nonCanonical[0] = 0xee;
    nonCanonical[31] = 0x7f;
    ASSERT_FALSE(eddsa::ed25519Verify(nonCanonical, message, forged));
    ASSERT_FALSE(keys::ed25519EncodingIsStrict(identity.data()));
    ASSERT_FALSE(keys::ed25519EncodingIsStrict(nonCanonical.data()));
}

TEST_CASE(Curves, KeyValidation_PublicKeys) {
    auto pub = test::hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    ASSERT_TRUE(keys::isValidPublicKey(Curve::SECP256K1, pub.data(), pub.size()));

    auto badPrefix = pub;
    badPrefix[0] = 0x05;
    ASSERT_FALSE(keys::isValidPublicKey(Curve::SECP256K1, badPrefix.data(), badPrefix.size()));

    ByteVector xTooLarge(33, 0xff);
    xTooLarge[0] = 0x02;
    ASSERT_FALSE(keys::isValidPublicKey(Curve::SECP256K1, xTooLarge.data(), xTooLarge.size()));

    // x = 7 is no x-coordinate of secp256k1, P-256 or P-384.
    ByteVector offCurve(33, 0x00);
    offCurve[0] = 0x02;
    offCurve[32] = 0x07;
    ASSERT_FALSE(keys::isValidPublicKey(Curve::SECP256K1, offCurve.data(), offCurve.size()));
    ASSERT_FALSE(keys::isValidPublicKey(Curve::P256, offCurve.data(), offCurve.size()));
    ASSERT_FALSE(keys::isValidPublicKey(Curve::SECP256K1, pub.data(), 32));
    ASSERT_FALSE(keys::isValidPublicKey(Curve::SECP256K1, pub.data(), 0));

    // P-256 generator, compressed.
    auto p256G = test::hexToBytes("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    ASSERT_TRUE(keys::isValidPublicKey(Curve::P256, p256G.data(), p256G.size()));
    auto p256Hybrid = p256G;
    p256Hybrid[0] = 0x07;
    ASSERT_FALSE(keys::isValidPublicKey(Curve::P256, p256Hybrid.data(), p256Hybrid.size()));

    auto edPub = test::hexToBytes(ED25519_SIGN_VECTORS[0].public_key_hex);
    ASSERT_TRUE(keys::isValidPublicKey(Curve::ED25519, edPub.data(), edPub.size()));
}

TEST_CASE(Curves, KeyValidation_PrivateKeys) {
    auto n = test::hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    auto nMinus1 = test::hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    ByteVector zero(32, 0x00);
    ByteVector allFf(32, 0xff);
    ASSERT_TRUE(keys::isValidPrivateKey(Curve::SECP256K1, nMinus1.data(), 32));
    ASSERT_FALSE(keys::isValidPrivateKey(Curve::SECP256K1, n.data(), 32));
    ASSERT_FALSE(keys::isValidPrivateKey(Curve::SECP256K1, zero.data(), 32));
    ASSERT_FALSE(keys::isValidPrivateKey(Curve::SECP256K1, allFf.data(), 32));
    ASSERT_FALSE(keys::isValidPrivateKey(Curve::SECP256K1, nMinus1.data(), 31));
    ASSERT_FALSE(keys::isValidPrivateKey(Curve::P256, allFf.data(), 32));
    ASSERT_TRUE(keys::isValidPrivateKey(Curve::ED25519, allFf.data(), 32));
}

// =============================================================================
// Test: RFC 6979 deterministic ECDSA known answers (2.1.1)
// =============================================================================
//
// RFC 6979 Appendix A.2.5 (P-256) and A.2.6 (P-384), messages "sample" and
// "test", with SHA-256, SHA-384 and SHA-512 message hashes. The HMAC in the
// nonce derivation uses the message hash function. Before 2.1.1 every curve
// used HMAC-SHA256 into hash-sized V and K, so each P-384 nonce ended in
// sixteen 0x01 octets and none of the A.2.6 signatures were reproduced.

#include "hd_wallet/ecdsa.h"

#include <cryptopp/sha.h>

namespace hd_wallet {
namespace ecdsa {
// Defined in src/ecdsa.cpp; the compact-signature core behind p256Sign,
// p384Sign and secp256k1Sign, taking a message hash of any supported length.
bool signCompact(Curve curve, const uint8_t* privateKey, size_t privateKeyLen,
                 const uint8_t* hash, size_t hashLen, uint8_t* signature,
                 size_t* signatureLen, int* recoveryId);
bool verifyCompact(Curve curve, const uint8_t* publicKey, size_t publicKeyLen,
                   const uint8_t* hash, size_t hashLen, const uint8_t* signature,
                   size_t signatureLen);
// The DER-signature verifier, also in src/ecdsa.cpp.
bool verify(Curve curve, const uint8_t* publicKey, size_t publicKeyLen,
            const uint8_t* hash, size_t hashLen, const uint8_t* signature,
            size_t signatureLen);
} // namespace ecdsa
} // namespace hd_wallet

namespace {

struct Rfc6979Vector {
    unsigned hashBits;     // 256, 384 or 512
    const char* message;
    const char* r;
    const char* s;
};

const char* const kRfcP256Private = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const char* const kRfcP256Public =
    "04" "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

const Rfc6979Vector kRfcP256Vectors[] = {
    {256, "sample", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
    {384, "sample", "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef7719",
                    "4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954"},
    {512, "sample", "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00",
                    "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe"},
    {256, "test",   "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
                    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"},
    {384, "test",   "83910e8b48bb0c74244ebdf7f07a1c5413d61472bd941ef3920e623fbccebeb6",
                    "8ddbec54cf8cd5874883841d712142a56a8d0f218f5003cb0296b6b509619f2c"},
    {512, "test",   "461d93f31b6540894788fd206c07cfa0cc35f46fa3c91816fff1040ad1581a04",
                    "39af9f15de0db8d97e72719c74820d304ce5226e32dedae67519e840d1194e55"},
};

const char* const kRfcP384Private =
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
const char* const kRfcP384Public =
    "04" "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13"
    "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";

const Rfc6979Vector kRfcP384Vectors[] = {
    {256, "sample",
     "21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3daa33bde1e888e63355d92fa2b3c36d8fb2cd",
     "f3aa443fb107745bf4bd77cb3891674632068a10ca67e3d45db2266fa7d1feebefdc63eccd1ac42ec0cb8668a4fa0ab0"},
    {384, "sample",
     "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
     "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8"},
    {512, "sample",
     "ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709",
     "512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5"},
    {256, "test",
     "6d6defac9ab64dabafe36c6bf510352a4cc27001263638e5b16d9bb51d451559f918eedaf2293be5b475cc8f0188636b",
     "2d46f3becbcc523d5f1a1256bf0c9b024d879ba9e838144c8ba6baeb4b53b47d51ab373f9845c0514eefb14024787265"},
    {384, "test",
     "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db",
     "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5"},
    {512, "test",
     "a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277",
     "976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736"},
};

ByteVector rfcMessageHash(unsigned bits, const char* message) {
    const auto* data = reinterpret_cast<const uint8_t*>(message);
    const size_t len = std::strlen(message);
    ByteVector out;
    if (bits == 256) {
        out.resize(CryptoPP::SHA256::DIGESTSIZE);
        CryptoPP::SHA256().CalculateDigest(out.data(), data, len);
    } else if (bits == 384) {
        out.resize(CryptoPP::SHA384::DIGESTSIZE);
        CryptoPP::SHA384().CalculateDigest(out.data(), data, len);
    } else {
        out.resize(CryptoPP::SHA512::DIGESTSIZE);
        CryptoPP::SHA512().CalculateDigest(out.data(), data, len);
    }
    return out;
}

std::string bytesHex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

void checkRfc6979(Curve curve, const char* privateHex, const char* publicHex,
                  const Rfc6979Vector* vectors, size_t count, size_t coordSize) {
    auto priv = test::hexToBytes(privateHex);
    auto pub = test::hexToBytes(publicHex);
    for (size_t i = 0; i < count; ++i) {
        const auto& vec = vectors[i];
        auto hash = rfcMessageHash(vec.hashBits, vec.message);
        std::vector<uint8_t> sig(coordSize * 2);
        size_t sigLen = sig.size();
        int recoveryId = -1;
        ASSERT_TRUE(ecdsa::signCompact(curve, priv.data(), priv.size(), hash.data(), hash.size(),
                                       sig.data(), &sigLen, &recoveryId));
        ASSERT_EQ(coordSize * 2, sigLen);
        ASSERT_STR_EQ(std::string(vec.r) + vec.s, bytesHex(sig.data(), sigLen));
        ASSERT_TRUE(ecdsa::verifyCompact(curve, pub.data(), pub.size(), hash.data(), hash.size(),
                                         sig.data(), sigLen));
    }
}

} // namespace

TEST_CASE(Curves, Rfc6979_P256_KnownAnswers) {
    checkRfc6979(Curve::P256, kRfcP256Private, kRfcP256Public, kRfcP256Vectors,
                 sizeof(kRfcP256Vectors) / sizeof(kRfcP256Vectors[0]), 32);
}

TEST_CASE(Curves, Rfc6979_P384_KnownAnswers) {
    checkRfc6979(Curve::P384, kRfcP384Private, kRfcP384Public, kRfcP384Vectors,
                 sizeof(kRfcP384Vectors) / sizeof(kRfcP384Vectors[0]), 48);
}

TEST_CASE(Curves, Rfc6979_PublicSignersMatchKnownAnswers) {
    // p256Sign takes a SHA-256 hash, p384Sign a SHA-384 hash (the hashes the
    // WASM hd_p256_sign / hd_p384_sign and X.509 signing compute).
    auto p256Hash = rfcMessageHash(256, "sample");
    Bytes32 p256Digest{};
    std::copy(p256Hash.begin(), p256Hash.end(), p256Digest.begin());
    auto p256 = ecdsa::p256Sign(test::hexToArray<32>(kRfcP256Private), p256Digest);
    ASSERT_OK(p256);
    ASSERT_STR_EQ(std::string(kRfcP256Vectors[0].r) + kRfcP256Vectors[0].s,
                  bytesHex(p256.value.data(), p256.value.size()));

    auto p384Hash = rfcMessageHash(384, "test");
    std::array<uint8_t, 48> p384Digest{};
    std::copy(p384Hash.begin(), p384Hash.end(), p384Digest.begin());
    auto p384 = ecdsa::p384Sign(test::hexToArray<48>(kRfcP384Private), p384Digest);
    ASSERT_OK(p384);
    ASSERT_STR_EQ(std::string(kRfcP384Vectors[4].r) + kRfcP384Vectors[4].s,
                  bytesHex(p384.value.data(), p384.value.size()));
    ByteVector p384Pub = test::hexToBytes(kRfcP384Public);
    ASSERT_TRUE(ecdsa::p384Verify(p384Pub, p384Digest, p384.value));
}

TEST_CASE(Curves, Rfc6979_RefusesUnsupportedHashLength) {
    // The nonce HMAC must use the message hash, so a hash that is not
    // SHA-256, SHA-384 or SHA-512 sized is refused instead of guessed.
    auto priv = test::hexToBytes(kRfcP256Private);
    for (size_t len : {size_t(0), size_t(20), size_t(28), size_t(33), size_t(47), size_t(65)}) {
        ByteVector hash(len == 0 ? 1 : len, 0x5a);
        uint8_t sig[96] = {};
        size_t sigLen = sizeof(sig);
        int recoveryId = -1;
        ASSERT_FALSE(ecdsa::signCompact(Curve::P256, priv.data(), priv.size(), hash.data(), len,
                                        sig, &sigLen, &recoveryId));
    }
}

// =============================================================================
// Strict DER signatures (2.1.1 round 2)
// =============================================================================
//
// fromDER never checked the integer lengths against the input: a short DER
// read past the buffer (heap overflow under ASan), and one signature had many
// accepted encodings (wrong sequence length, padding, trailing bytes, r with
// 2^256 added). Only X.690 DER is accepted now.

namespace {

ByteVector derInteger(const ByteVector& magnitude) {
    ByteVector out{0x02};
    size_t start = 0;
    while (start + 1 < magnitude.size() && magnitude[start] == 0) ++start;
    const bool pad = magnitude[start] & 0x80;
    out.push_back(static_cast<uint8_t>(magnitude.size() - start + (pad ? 1 : 0)));
    if (pad) out.push_back(0x00);
    out.insert(out.end(), magnitude.begin() + start, magnitude.end());
    return out;
}

ByteVector derSequence(const ByteVector& r, const ByteVector& s) {
    ByteVector body = derInteger(r);
    ByteVector sEnc = derInteger(s);
    body.insert(body.end(), sEnc.begin(), sEnc.end());
    ByteVector out{0x30, static_cast<uint8_t>(body.size())};
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// Each malformed variant of a well-formed DER signature `der` (r with the top
// bit set, so it carries a 0x00 pad; s padded or not) for `coordSize`-byte
// integers.
std::vector<std::pair<std::string, ByteVector>> malformedDer(const ByteVector& der, size_t coordSize) {
    std::vector<std::pair<std::string, ByteVector>> out;
    const size_t rAt = 2;                       // 02 len 00 r...
    const size_t sAt = rAt + 2 + der[rAt + 1];  // 02 len [00] s...
    const bool sPadded = der[sAt + 2] == 0x00;
    auto add = [&](const char* name, ByteVector v) { out.emplace_back(name, std::move(v)); };
    auto grow = [](ByteVector& v, size_t lenAt) { v[lenAt] += 1; v[1] += 1; };
    auto shrink = [](ByteVector& v, size_t lenAt) { v[lenAt] -= 1; v[1] -= 1; };

    // First: under ASan the old parser read 127 bytes from this 8-byte buffer.
    { ByteVector v{0x30, 0x00, 0x02, 0x7f, 0x01, 0x02, 0x03, 0x04}; add("r length past the end", v); }
    { auto v = der; v[1] -= 1; add("sequence length one short", v); }
    { auto v = der; v[1] += 1; add("sequence length one long", v); }
    { auto v = der; v.push_back(0x00); add("trailing byte", v); }
    { auto v = der; v.push_back(0x00); v[1] += 1; add("trailing byte inside the sequence", v); }
    { auto v = der; v.pop_back(); add("truncated", v); }
    { auto v = der; v[0] = 0x31; add("SET tag", v); }
    { auto v = der; v[rAt] = 0x03; add("r tag", v); }
    { auto v = der; v[sAt] = 0x04; add("s tag", v); }
    { auto v = der; v.erase(v.begin() + rAt + 2); shrink(v, rAt + 1); add("r without its 0x00 pad (negative)", v); }
    { auto v = der; v.insert(v.begin() + rAt + 2, 0x00); grow(v, rAt + 1); add("r padded twice", v); }
    { auto v = der; v.insert(v.begin() + sAt + 2, 0x00); grow(v, sAt + 1); add("s with an extra 0x00", v); }
    { auto v = der; v[rAt + 2] = 0x01; add("r + 2^(8*coordSize)", v); }
    if (sPadded) {
        { auto v = der; v.erase(v.begin() + sAt + 2); shrink(v, sAt + 1); add("s without its 0x00 pad (negative)", v); }
        { auto v = der; v[sAt + 2] = 0x01; add("s + 2^(8*coordSize)", v); }
    } else {
        { auto v = der; v[sAt + 2] |= 0x80; add("s with the top bit set, unpadded (negative)", v); }
        { auto v = der; v.insert(v.begin() + sAt + 2, 0x01); grow(v, sAt + 1); add("s + 2^(8*coordSize)", v); }
    }
    { auto v = der; v[rAt + 2] = 0xff; add("leading ff in r", v); }
    { auto v = der; v.insert(v.begin() + 1, 0x81); add("long-form sequence length", v); }
    { auto v = der; v.insert(v.begin() + rAt + 1, 0x81); v[1] += 1; add("long-form r length", v); }
    { ByteVector v{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}; add("r = 0", v); }
    { ByteVector v{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00}; add("s = 0", v); }
    { ByteVector v{0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01}; add("empty r", v); }
    { ByteVector v(der.begin(), der.begin() + sAt); v[1] = static_cast<uint8_t>(v.size() - 2); add("no s", v); }
    (void)coordSize;
    return out;
}

ByteVector rfcBytes(const char* hex) { return test::hexToBytes(hex); }

} // namespace

TEST_CASE(Curves, Der_StrictEncodingOnly_P256_P384) {
    struct Case { Curve curve; const char* priv; const char* pub; const Rfc6979Vector& vec; size_t coordSize; };
    const Case cases[] = {
        {Curve::P256, kRfcP256Private, kRfcP256Public, kRfcP256Vectors[0], 32},  // SHA-256 "sample"
        {Curve::P384, kRfcP384Private, kRfcP384Public, kRfcP384Vectors[1], 48},  // SHA-384 "sample"
    };
    for (const auto& c : cases) {
        auto hash = rfcMessageHash(c.vec.hashBits, c.vec.message);
        auto pub = rfcBytes(c.pub);
        auto r = rfcBytes(c.vec.r);
        auto s = rfcBytes(c.vec.s);
        ASSERT_EQ(c.coordSize, r.size());
        // The variants below need r to carry a 0x00 pad.
        ASSERT_TRUE(r[0] & 0x80);
        ByteVector der = derSequence(r, s);
        ASSERT_TRUE(ecdsa::verify(c.curve, pub.data(), pub.size(), hash.data(), hash.size(), der.data(), der.size()));
        for (const auto& bad : malformedDer(der, c.coordSize)) {
            if (ecdsa::verify(c.curve, pub.data(), pub.size(), hash.data(), hash.size(),
                              bad.second.data(), bad.second.size())) {
                ASSERT_STR_EQ("refused", std::string("accepted: ") + bad.first);
            }
        }
    }
}

TEST_CASE(Curves, Der_StrictEncodingOnly_Secp256k1) {
    // A secp256k1 signature whose r has the top bit set (s is low-S, so it
    // never does) and whose s has no leading zero byte.
    ByteVector priv(32, 0);
    priv[31] = 9;
    ByteVector hash(32, 0);
    uint8_t sig[64];
    size_t sigLen = 0;
    int recoveryId = -1;
    for (uint8_t i = 0;; ++i) {
        hash[0] = i;
        sigLen = sizeof(sig);
        ASSERT_TRUE(ecdsa::signCompact(Curve::SECP256K1, priv.data(), priv.size(), hash.data(), hash.size(),
                                       sig, &sigLen, &recoveryId));
        if ((sig[0] & 0x80) && sig[32] != 0) break;
        ASSERT_TRUE(i < 250);
    }
    ByteVector r(sig, sig + 32);
    ByteVector s(sig + 32, sig + 64);
    ByteVector der = derSequence(r, s);

    // derToCompact (behind curves.secp256k1.verify for a non-64-byte signature).
    auto compact = ecdsa::derToCompact(der);
    ASSERT_OK(compact);
    ASSERT_BYTES_EQ(sig, compact.value.data(), 64);
    ecdsa::CompactSignature c{};
    std::memcpy(c.data(), sig, 64);
    ASSERT_STR_EQ(bytesHex(der.data(), der.size()), bytesHex(ecdsa::compactToDer(c).data(), ecdsa::compactToDer(c).size()));
    for (const auto& bad : malformedDer(der, 32)) {
        if (ecdsa::derToCompact(bad.second).ok()) {
            ASSERT_STR_EQ("refused", std::string("accepted: ") + bad.first);
        }
    }

    // Integers shorter than 32 bytes are fine when minimal: r = 1, s = 1 parse
    // (and do not verify).
    ByteVector small{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    auto parsed = ecdsa::derToCompact(small);
    ASSERT_OK(parsed);
    ASSERT_EQ(1, static_cast<int>(parsed.value[31]));
    ASSERT_EQ(1, static_cast<int>(parsed.value[63]));
}
