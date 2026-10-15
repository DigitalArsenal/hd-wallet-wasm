/**
 * libp2p PeerID and IPNS hash derivation
 *
 * Implements the libp2p peer identity spec:
 *   public key → protobuf serialize → multihash → peerID
 *   peerID → CIDv1(libp2p-key codec) → multibase encode → IPNS hash
 */

#include "hd_wallet/libp2p.h"
#include "hd_wallet/types.h"
#include "hd_wallet/config.h"
#include "key_validation.h"

#include <cryptopp/sha.h>
#include <cstring>
#include <cstdint>
#include <vector>

using hd_wallet::Error;

// Forward declaration — implemented in coins/coin.cpp
extern "C" int32_t hd_base58_encode(
    const uint8_t* data, size_t data_len,
    char* output, size_t output_size
);

namespace {

// =============================================================================
// Internal helpers
// =============================================================================

// libp2p KeyType enum values
constexpr int32_t KEYTYPE_ED25519   = 1;
constexpr int32_t KEYTYPE_SECP256K1 = 2;
constexpr int32_t KEYTYPE_ECDSA     = 3; // P-256

// Curve enum values (must match JS Curve enum)
constexpr int32_t CURVE_SECP256K1 = 0;
constexpr int32_t CURVE_ED25519   = 1;
constexpr int32_t CURVE_P256      = 2;

// libp2p-key multicodec
constexpr uint8_t LIBP2P_KEY_CODEC = 0x72;

// Multihash identity code
constexpr uint8_t MULTIHASH_IDENTITY = 0x00;
// Multihash SHA-256 code
constexpr uint8_t MULTIHASH_SHA256 = 0x12;

// Max protobuf size before SHA-256 hash is used
constexpr size_t IDENTITY_THRESHOLD = 42;

/**
 * Map curve enum to libp2p KeyType.
 * Returns -1 if unsupported.
 */
int32_t curveToKeyType(int32_t curve) {
    switch (curve) {
        case CURVE_SECP256K1: return KEYTYPE_SECP256K1;
        case CURVE_ED25519:   return KEYTYPE_ED25519;
        case CURVE_P256:      return KEYTYPE_ECDSA;
        default: return -1;
    }
}

/**
 * Encode unsigned integer as LEB128 varint into buffer.
 * Returns number of bytes written.
 */
size_t encodeVarint(uint32_t value, uint8_t* out) {
    size_t i = 0;
    while (value >= 0x80) {
        out[i++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[i++] = static_cast<uint8_t>(value & 0x7f);
    return i;
}

/**
 * Serialize public key in libp2p protobuf format.
 * message PublicKey { KeyType Type = 1; bytes Data = 2; }
 *
 * Returns total bytes written to out.
 * out must be at least pubkey_len + 6 bytes.
 */
size_t serializeProtobuf(const uint8_t* pubkey, size_t pubkey_len,
                         int32_t keyType, uint8_t* out) {
    size_t offset = 0;

    // Field 1 (KeyType): tag = (1 << 3) | 0 = 0x08, then varint value
    out[offset++] = 0x08;
    offset += encodeVarint(static_cast<uint32_t>(keyType), out + offset);

    // Field 2 (Data): tag = (2 << 3) | 2 = 0x12, then length varint, then data
    out[offset++] = 0x12;
    offset += encodeVarint(static_cast<uint32_t>(pubkey_len), out + offset);
    std::memcpy(out + offset, pubkey, pubkey_len);
    offset += pubkey_len;

    return offset;
}

/**
 * Compute peerID multihash bytes from a public key.
 * Returns total bytes written to out, or negative error.
 */
int32_t computePeerId(const uint8_t* pubkey, size_t pubkey_len,
                      int32_t curve, uint8_t* out, size_t out_size) {
    int32_t keyType = curveToKeyType(curve);
    if (keyType < 0) {
        return -static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    // The key must be a valid public key of its curve in the libp2p form:
    // secp256k1 compressed (33 bytes), Ed25519 32 bytes, P-256 compressed or
    // uncompressed. This also bounds pubkey_len for the protobuf buffer.
    const bool lengthOk =
        (curve == CURVE_SECP256K1 && pubkey_len == 33) ||
        (curve == CURVE_ED25519 && pubkey_len == 32) ||
        (curve == CURVE_P256 && (pubkey_len == 33 || pubkey_len == 65));
    if (!lengthOk ||
        !hd_wallet::keys::isValidPublicKey(static_cast<hd_wallet::Curve>(curve), pubkey, pubkey_len)) {
        return -static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    // Serialize protobuf (max overhead: 6 bytes for tags + varints)
    uint8_t protobuf[128];
    size_t pbLen = serializeProtobuf(pubkey, pubkey_len, keyType, protobuf);

    if (pbLen <= IDENTITY_THRESHOLD) {
        // Identity multihash: code(0x00) + varint(length) + data
        uint8_t lenVarint[2];
        size_t lenSize = encodeVarint(static_cast<uint32_t>(pbLen), lenVarint);
        size_t totalLen = 1 + lenSize + pbLen;
        if (out_size < totalLen) {
            return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
        }
        size_t offset = 0;
        out[offset++] = MULTIHASH_IDENTITY;
        std::memcpy(out + offset, lenVarint, lenSize);
        offset += lenSize;
        std::memcpy(out + offset, protobuf, pbLen);
        return static_cast<int32_t>(totalLen);
    } else {
        // SHA-256 multihash: code(0x12) + length(0x20) + sha256(data)
        if (out_size < 34) {
            return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
        }
        out[0] = MULTIHASH_SHA256;
        out[1] = 0x20; // 32
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(out + 2, protobuf, pbLen);
        return 34;
    }
}

/**
 * Build CIDv1 bytes: varint(1) + varint(codec) + multihash
 * Returns total bytes written to out.
 */
size_t buildCidV1(const uint8_t* multihash, size_t mhLen, uint8_t* out) {
    size_t offset = 0;
    // Version 1
    offset += encodeVarint(0x01, out + offset);
    // Codec: libp2p-key (0x72)
    offset += encodeVarint(LIBP2P_KEY_CODEC, out + offset);
    // Multihash
    std::memcpy(out + offset, multihash, mhLen);
    offset += mhLen;
    return offset;
}

// =============================================================================
// Base32 / Base36 encoding
// =============================================================================

static const char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";
static const char BASE36_ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/**
 * RFC 4648 base32 lowercase, no padding.
 * Returns number of characters written (not including null terminator).
 */
size_t base32LowerEncode(const uint8_t* data, size_t len, char* out) {
    size_t outLen = 0;
    int bits = 0;
    uint32_t value = 0;

    for (size_t i = 0; i < len; i++) {
        value = (value << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            out[outLen++] = BASE32_ALPHABET[(value >> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }
    if (bits > 0) {
        out[outLen++] = BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
    }
    out[outLen] = '\0';
    return outLen;
}

/**
 * Base36 lowercase encoding (big-endian byte array to base36 string).
 * Similar to base58 but with alphabet 0-9a-z.
 * Returns number of characters written (not including null terminator).
 */
size_t base36LowerEncode(const uint8_t* data, size_t len, char* out) {
    // Count leading zeros
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    // Allocate enough space: ceil(len * log(256) / log(36)) ~ len * 1.55
    size_t bufSize = static_cast<size_t>(len * 155 / 100) + 2;
    std::vector<uint8_t> b36(bufSize, 0);

    for (size_t i = zeros; i < len; i++) {
        uint32_t carry = data[i];
        for (size_t j = bufSize; j > 0; j--) {
            carry += 256u * b36[j - 1];
            b36[j - 1] = static_cast<uint8_t>(carry % 36);
            carry /= 36;
        }
    }

    // Skip leading zeros in b36
    size_t it = 0;
    while (it < bufSize && b36[it] == 0) it++;

    // Write output
    size_t outLen = 0;
    for (size_t i = 0; i < zeros; i++) {
        out[outLen++] = '0';
    }
    while (it < bufSize) {
        out[outLen++] = BASE36_ALPHABET[b36[it++]];
    }
    out[outLen] = '\0';
    return outLen;
}

} // anonymous namespace

// =============================================================================
// Exported C API
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_libp2p_peer_id(
    const uint8_t* public_key, size_t pubkey_len,
    int32_t curve,
    uint8_t* output, size_t output_size
) {
    if (!public_key || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    return computePeerId(public_key, pubkey_len, curve, output, output_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_libp2p_peer_id_string(
    const uint8_t* public_key, size_t pubkey_len,
    int32_t curve,
    char* output, size_t output_size
) {
    if (!public_key || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    uint8_t peerId[64];
    int32_t peerIdLen = computePeerId(public_key, pubkey_len, curve, peerId, sizeof(peerId));
    if (peerIdLen < 0) return peerIdLen;

    return hd_base58_encode(peerId, static_cast<size_t>(peerIdLen), output, output_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_libp2p_ipns_hash(
    const uint8_t* public_key, size_t pubkey_len,
    int32_t curve,
    char* output, size_t output_size
) {
    if (!public_key || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    uint8_t peerId[64];
    int32_t peerIdLen = computePeerId(public_key, pubkey_len, curve, peerId, sizeof(peerId));
    if (peerIdLen < 0) return peerIdLen;

    uint8_t cid[128];
    size_t cidLen = buildCidV1(peerId, static_cast<size_t>(peerIdLen), cid);

    // 'k' prefix + base36lower(cid) + null. Encode locally and check the
    // caller's size before writing anything to it.
    char encoded[256];
    const size_t encodedLen = base36LowerEncode(cid, cidLen, encoded);
    if (output_size < 1 + encodedLen + 1) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    output[0] = 'k';
    std::memcpy(output + 1, encoded, encodedLen + 1);
    return static_cast<int32_t>(Error::OK);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_libp2p_ipns_hash_base32(
    const uint8_t* public_key, size_t pubkey_len,
    int32_t curve,
    char* output, size_t output_size
) {
    if (!public_key || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    uint8_t peerId[64];
    int32_t peerIdLen = computePeerId(public_key, pubkey_len, curve, peerId, sizeof(peerId));
    if (peerIdLen < 0) return peerIdLen;

    uint8_t cid[128];
    size_t cidLen = buildCidV1(peerId, static_cast<size_t>(peerIdLen), cid);

    // 'b' prefix + base32lower(cid) + null. Encode locally and check the
    // caller's size before writing anything to it.
    char encoded[256];
    const size_t encodedLen = base32LowerEncode(cid, cidLen, encoded);
    if (output_size < 1 + encodedLen + 1) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    output[0] = 'b';
    std::memcpy(output + 1, encoded, encodedLen + 1);
    return static_cast<int32_t>(Error::OK);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_encode_base32lower(
    const uint8_t* data, size_t data_len,
    char* output, size_t output_size
) {
    if (!data || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    // base32 output length: ceil(data_len * 8 / 5)
    size_t needed = (data_len * 8 + 4) / 5 + 1; // +1 for null
    if (output_size < needed) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    base32LowerEncode(data, data_len, output);
    return static_cast<int32_t>(Error::OK);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_encode_base36lower(
    const uint8_t* data, size_t data_len,
    char* output, size_t output_size
) {
    if (!data || !output) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    // base36 output length estimate: ceil(data_len * 1.55) + 1
    size_t needed = static_cast<size_t>(data_len * 155 / 100) + 3;
    if (output_size < needed) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    base36LowerEncode(data, data_len, output);
    return static_cast<int32_t>(Error::OK);
}
