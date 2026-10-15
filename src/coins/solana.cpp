/**
 * @file solana.cpp
 * @brief Solana Support Implementation
 */

#include "hd_wallet/coins/solana.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Well-Known Solana Addresses
// =============================================================================

namespace solana_addresses {
  const char* SYSTEM_PROGRAM = "11111111111111111111111111111111";
  const char* TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  const char* TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
  const char* ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
  const char* MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
  const char* RENT_SYSVAR = "SysvarRent111111111111111111111111111111111";
  const char* CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111";
  const char* STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";
  const char* VOTE_PROGRAM = "Vote111111111111111111111111111111111111111";
}

// =============================================================================
// Solana Address Generation
// =============================================================================

Result<std::string> solanaAddress(const Bytes32& public_key) {
  // Solana addresses are simply Base58-encoded public keys
  ByteVector pubkey(public_key.begin(), public_key.end());
  return Result<std::string>::success(base58Encode(pubkey));
}

Result<Bytes32> solanaAddressToPublicKey(const std::string& address) {
  auto decoded = base58Decode(address);
  if (!decoded.ok()) {
    return Result<Bytes32>::fail(decoded.error);
  }

  if (decoded.value.size() != 32) {
    return Result<Bytes32>::fail(Error::INVALID_ADDRESS);
  }

  Bytes32 result;
  std::copy(decoded.value.begin(), decoded.value.end(), result.begin());
  return Result<Bytes32>::success(std::move(result));
}

// =============================================================================
// Solana Address Validation
// =============================================================================

Error validateSolanaAddress(const std::string& address, bool verify_curve) {
  // Decode from Base58
  auto decoded = base58Decode(address);
  if (!decoded.ok()) {
    return Error::INVALID_ADDRESS;
  }

  // Must be 32 bytes
  if (decoded.value.size() != 32) {
    return Error::INVALID_ADDRESS;
  }

  // Optionally verify it's on the Ed25519 curve
  if (verify_curve) {
    // For Ed25519, not all 32-byte values are valid public keys
    // A full implementation would verify the point is on curve
    // For now, we just check basic validity
    try {
      CryptoPP::ed25519::Verifier verifier(decoded.value.data());
      // If we can create a verifier, the key is valid
    } catch (...) {
      return Error::INVALID_PUBLIC_KEY;
    }
  }

  return Error::OK;
}

bool isSolanaSystemProgram(const std::string& address) {
  return address == solana_addresses::SYSTEM_PROGRAM;
}

bool isSolanaTokenProgram(const std::string& address) {
  return address == solana_addresses::TOKEN_PROGRAM ||
         address == solana_addresses::TOKEN_2022_PROGRAM;
}

// =============================================================================
// Solana Program Derived Addresses (PDA)
// =============================================================================

namespace {

// =============================================================================
// Ed25519 on-curve check for PDA validation
//
// PDAs must NOT be valid Ed25519 public keys (must be "off curve").
// We cannot rely on Crypto++ exceptions in WASM (-fignore-exceptions),
// so we implement the curve check mathematically.
//
// Ed25519 uses the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
// where p = 2^255 - 19, d = -121665/121666 mod p
//
// A 32-byte encoding represents a point by encoding y (255 bits) and
// the sign of x (1 bit). To check if it's on the curve, we:
// 1. Decode y from the 32 bytes
// 2. Compute x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
// 3. Try to compute x = sqrt(x^2) mod p
// 4. If sqrt exists, the point is on-curve; otherwise, off-curve
// =============================================================================

// Simple modular arithmetic using 4 x 64-bit limbs for p = 2^255 - 19
// We use schoolbook multiplication with 128-bit intermediates.

// p = 2^255 - 19 in little-endian 64-bit limbs
static const uint64_t P[4] = {
    0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL
};

// d = -121665/121666 mod p (from RFC 8032)
// d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
static const uint64_t D[4] = {
    0x75EB4DCA135978A3ULL, 0x00700A4D4141D8ABULL,
    0x8CC740797779E898ULL, 0x52036CBC148B6262ULL
};

// Compare two 256-bit numbers (4 x 64-bit LE limbs)
// Returns: -1 if a < b, 0 if equal, 1 if a > b
static int cmp256(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Subtract: r = a - b mod p (assumes a, b < p)
static void sub_mod_p(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        __int128 diff = static_cast<__int128>(a[i]) - static_cast<__int128>(b[i]) - borrow;
        r[i] = static_cast<uint64_t>(diff);
        borrow = (diff < 0) ? 1 : 0;
    }
    if (borrow) {
        // Add p back
        __int128 carry = 0;
        for (int i = 0; i < 4; i++) {
            __int128 s = static_cast<__int128>(r[i]) + static_cast<__int128>(P[i]) + carry;
            r[i] = static_cast<uint64_t>(s);
            carry = s >> 64;
        }
    }
}

// Add: r = a + b mod p
static void add_mod_p(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        __int128 s = static_cast<__int128>(a[i]) + static_cast<__int128>(b[i]) + carry;
        r[i] = static_cast<uint64_t>(s);
        carry = s >> 64;
    }
    // Reduce if >= p
    if (carry || cmp256(r, P) >= 0) {
        __int128 borrow = 0;
        for (int i = 0; i < 4; i++) {
            __int128 diff = static_cast<__int128>(r[i]) - static_cast<__int128>(P[i]) - borrow;
            r[i] = static_cast<uint64_t>(diff);
            borrow = (diff < 0) ? 1 : 0;
        }
    }
}

// Multiply: r = a * b mod p using schoolbook with 128-bit intermediates
static void mul_mod_p(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    // Full 512-bit product in 8 limbs
    __int128 t[8] = {};
    for (int i = 0; i < 4; i++) {
        __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            __int128 prod = static_cast<__int128>(a[i]) * static_cast<__int128>(b[j]) + t[i + j] + carry;
            t[i + j] = prod & 0xFFFFFFFFFFFFFFFFULL;
            carry = prod >> 64;
        }
        t[i + 4] += carry;
    }

    // Barrett-style reduction mod p = 2^255 - 19
    // Since p = 2^255 - 19, we have: x mod p = (x_lo + 19 * x_hi * 2) mod p
    // where x = x_lo + x_hi * 2^255
    //
    // More precisely: for a 512-bit number stored in t[0..7],
    // split at bit 255: low part = t[0..3] with t[3] masked to 63 bits,
    // high part = (t[3] >> 63) | (t[4] << 1) | ...
    // Then result = low + 19 * high (mod p), repeating until < p.

    uint64_t lo[4], hi[4];
    lo[0] = static_cast<uint64_t>(t[0]);
    lo[1] = static_cast<uint64_t>(t[1]);
    lo[2] = static_cast<uint64_t>(t[2]);
    lo[3] = static_cast<uint64_t>(t[3]) & 0x7FFFFFFFFFFFFFFFULL;

    // high = full_product >> 255
    uint64_t bit63_of_t3 = static_cast<uint64_t>(t[3]) >> 63;
    hi[0] = (static_cast<uint64_t>(t[4]) << 1) | bit63_of_t3;
    hi[1] = (static_cast<uint64_t>(t[5]) << 1) | (static_cast<uint64_t>(t[4]) >> 63);
    hi[2] = (static_cast<uint64_t>(t[6]) << 1) | (static_cast<uint64_t>(t[5]) >> 63);
    hi[3] = (static_cast<uint64_t>(t[7]) << 1) | (static_cast<uint64_t>(t[6]) >> 63);

    // Multiply hi by 19 and add to lo
    __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        __int128 prod = static_cast<__int128>(hi[i]) * 19 + static_cast<__int128>(lo[i]) + carry;
        lo[i] = static_cast<uint64_t>(prod);
        carry = prod >> 64;
    }

    // One more reduction step if needed (carry from the multiply-add)
    // carry * 2^256 mod p = carry * 19 * 2 (since 2^256 = 2 * 2^255 = 2 * (p+19) = 2p + 38)
    // Actually 2^256 mod p = 38
    uint64_t c = static_cast<uint64_t>(carry) * 38;
    // But also check if lo[3] >= 2^63 (meaning >= 2^255)
    uint64_t over = lo[3] >> 63;
    lo[3] &= 0x7FFFFFFFFFFFFFFFULL;
    c += over * 19;

    carry = 0;
    __int128 s = static_cast<__int128>(lo[0]) + c;
    lo[0] = static_cast<uint64_t>(s);
    carry = s >> 64;
    for (int i = 1; i < 4; i++) {
        s = static_cast<__int128>(lo[i]) + carry;
        lo[i] = static_cast<uint64_t>(s);
        carry = s >> 64;
    }

    // Final reduction
    if (carry || cmp256(lo, P) >= 0) {
        __int128 borrow = 0;
        for (int i = 0; i < 4; i++) {
            __int128 diff = static_cast<__int128>(lo[i]) - static_cast<__int128>(P[i]) - borrow;
            lo[i] = static_cast<uint64_t>(diff);
            borrow = (diff < 0) ? 1 : 0;
        }
    }

    r[0] = lo[0]; r[1] = lo[1]; r[2] = lo[2]; r[3] = lo[3];
}

// Square: r = a^2 mod p
static void sqr_mod_p(uint64_t r[4], const uint64_t a[4]) {
    mul_mod_p(r, a, a);
}

// Power: r = base^exp mod p (exp as byte array, big-endian, exp_len bytes)
static void pow_mod_p(uint64_t r[4], const uint64_t base[4], const uint8_t* exp, size_t exp_len) {
    // r = 1
    r[0] = 1; r[1] = 0; r[2] = 0; r[3] = 0;
    uint64_t tmp[4];
    std::memcpy(tmp, base, sizeof(tmp));

    for (int i = static_cast<int>(exp_len) - 1; i >= 0; i--) {
        uint8_t byte = exp[i];
        for (int bit = 0; bit < 8; bit++) {
            if (byte & 1) {
                mul_mod_p(r, r, tmp);
            }
            sqr_mod_p(tmp, tmp);
            byte >>= 1;
        }
    }
}

// Decode 32 bytes (little-endian) into 4 x 64-bit limbs
static void decode256(uint64_t out[4], const uint8_t* bytes) {
    for (int i = 0; i < 4; i++) {
        out[i] = 0;
        for (int j = 0; j < 8; j++) {
            out[i] |= static_cast<uint64_t>(bytes[i * 8 + j]) << (8 * j);
        }
    }
}

// Check if a 32-byte value is a valid Ed25519 public key (on the curve)
// Returns true if ON curve, false if off curve
bool isOnEd25519Curve(const uint8_t* bytes) {
    // Ed25519 point encoding: 32 bytes, little-endian y coordinate
    // with the sign of x in the top bit of the last byte

    // Extract y (clear the sign bit)
    uint8_t y_bytes[32];
    std::memcpy(y_bytes, bytes, 32);
    y_bytes[31] &= 0x7F;  // Clear sign bit

    uint64_t y[4];
    decode256(y, y_bytes);

    // Check y < p
    if (cmp256(y, P) >= 0) {
        return false;
    }

    // Compute y^2 mod p
    uint64_t y2[4];
    sqr_mod_p(y2, y);

    // Compute u = y^2 - 1 mod p
    uint64_t one[4] = {1, 0, 0, 0};
    uint64_t u[4];
    sub_mod_p(u, y2, one);

    // Compute v = d * y^2 + 1 mod p
    uint64_t dy2[4];
    mul_mod_p(dy2, D, y2);
    uint64_t v[4];
    add_mod_p(v, dy2, one);

    // Compute v^{-1} = v^{p-2} mod p
    // p - 2 = 2^255 - 21
    uint8_t p_minus_2[32];
    std::memcpy(p_minus_2, P, 32);
    // Subtract 2 from P (little-endian): P[0] = 0xFFFFFFFFFFFFFFED, so P-2 has [0] = 0xFFFFFFFFFFFFFFEB
    // We need the byte representation
    for (int i = 0; i < 32; i++) {
        p_minus_2[i] = reinterpret_cast<const uint8_t*>(P)[i];
    }
    // Subtract 2 from the little-endian number
    uint16_t borrow = 2;
    for (int i = 0; i < 32 && borrow; i++) {
        uint16_t val = p_minus_2[i];
        if (val >= borrow) {
            p_minus_2[i] = static_cast<uint8_t>(val - borrow);
            borrow = 0;
        } else {
            p_minus_2[i] = static_cast<uint8_t>(256 + val - borrow);
            borrow = 1;
        }
    }

    uint64_t v_inv[4];
    pow_mod_p(v_inv, v, p_minus_2, 32);

    // x^2 = u * v^{-1} mod p
    uint64_t x2[4];
    mul_mod_p(x2, u, v_inv);

    // Check if x^2 is zero (valid: x = 0)
    if (x2[0] == 0 && x2[1] == 0 && x2[2] == 0 && x2[3] == 0) {
        // x = 0 is on curve if the sign bit is 0
        return (bytes[31] & 0x80) == 0;
    }

    // Compute candidate x = x2^{(p+3)/8} mod p
    // (p+3)/8 = (2^255 - 19 + 3) / 8 = (2^255 - 16) / 8 = 2^252 - 2
    uint8_t exp_bytes[32] = {};
    // 2^252 - 2 in little-endian bytes
    // 2^252 = 1 << 252 = byte 31 has bit 4 set (252 = 31*8 + 4)
    // Actually: 252/8 = 31 remainder 4, so byte[31] bit 4
    // But we have 32 bytes. 252 = 31*8+4 means byte index 31, bit 4
    exp_bytes[31] = 0x10;  // 2^252
    // Subtract 2
    borrow = 2;
    for (int i = 0; i < 32 && borrow; i++) {
        uint16_t val = exp_bytes[i];
        if (val >= borrow) {
            exp_bytes[i] = static_cast<uint8_t>(val - borrow);
            borrow = 0;
        } else {
            exp_bytes[i] = static_cast<uint8_t>(256 + val - borrow);
            borrow = 1;
        }
    }

    uint64_t x[4];
    pow_mod_p(x, x2, exp_bytes, 32);

    // Verify: x^2 == x2 mod p?
    uint64_t x_sq[4];
    sqr_mod_p(x_sq, x);
    if (cmp256(x_sq, x2) == 0) {
        return true;  // On curve
    }

    // Try x * sqrt(-1) mod p
    // sqrt(-1) mod p = 2^{(p-1)/4} mod p
    // = 19681161376707505956807079304988542015446066515923890162744021073123829784752
    static const uint64_t SQRT_M1[4] = {
        0xC4EE1B274A0EA0B0ULL, 0x2F431806AD2FE478ULL,
        0x2B4D00993DFBD7A7ULL, 0x2B8324804FC1DF0BULL
    };

    uint64_t x_alt[4];
    mul_mod_p(x_alt, x, SQRT_M1);
    sqr_mod_p(x_sq, x_alt);
    if (cmp256(x_sq, x2) == 0) {
        return true;  // On curve
    }

    return false;  // Off curve
}

// Check if a point is NOT on the Ed25519 curve
// PDAs must NOT be valid public keys
bool isOffCurve(const uint8_t* bytes) {
    return !isOnEd25519Curve(bytes);
}

}  // namespace

Result<std::pair<std::string, uint8_t>> findProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
) {
  // Try bump seeds from 255 down to 0
  for (int bump = 255; bump >= 0; bump--) {
    // Create seeds with bump
    std::vector<ByteVector> seeds_with_bump = seeds;
    seeds_with_bump.push_back({static_cast<uint8_t>(bump)});

    auto result = createProgramAddress(program_id, seeds_with_bump);
    if (result.ok()) {
      return Result<std::pair<std::string, uint8_t>>::success(
        std::make_pair(result.value, static_cast<uint8_t>(bump))
      );
    }
  }

  return Result<std::pair<std::string, uint8_t>>::fail(Error::KEY_DERIVATION_FAILED);
}

Result<std::string> createProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
) {
  // Concatenate: seeds + program_id + "ProgramDerivedAddress"
  ByteVector data;

  // Add seeds
  for (const auto& seed : seeds) {
    if (seed.size() > 32) {
      return Result<std::string>::fail(Error::INVALID_ARGUMENT);
    }
    data.insert(data.end(), seed.begin(), seed.end());
  }

  // Add program_id
  data.insert(data.end(), program_id.begin(), program_id.end());

  // Add marker
  const char* marker = "ProgramDerivedAddress";
  data.insert(data.end(), marker, marker + 21);

  // SHA256 hash
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), data.data(), data.size());

  // Verify it's off curve (valid PDA)
  if (!isOffCurve(hash.data())) {
    return Result<std::string>::fail(Error::INVALID_ADDRESS);
  }

  // Encode as address
  return solanaAddress(hash);
}

Result<std::string> getAssociatedTokenAddress(
  const std::string& wallet_address,
  const std::string& mint_address
) {
  // Decode addresses
  auto wallet = solanaAddressToPublicKey(wallet_address);
  if (!wallet.ok()) return Result<std::string>::fail(wallet.error);

  auto mint = solanaAddressToPublicKey(mint_address);
  if (!mint.ok()) return Result<std::string>::fail(mint.error);

  auto token_program = solanaAddressToPublicKey(solana_addresses::TOKEN_PROGRAM);
  if (!token_program.ok()) return Result<std::string>::fail(token_program.error);

  auto ata_program = solanaAddressToPublicKey(solana_addresses::ASSOCIATED_TOKEN_PROGRAM);
  if (!ata_program.ok()) return Result<std::string>::fail(ata_program.error);

  // Seeds: [wallet, token_program, mint]
  std::vector<ByteVector> seeds = {
    ByteVector(wallet.value.begin(), wallet.value.end()),
    ByteVector(token_program.value.begin(), token_program.value.end()),
    ByteVector(mint.value.begin(), mint.value.end())
  };

  auto result = findProgramAddress(ata_program.value, seeds);
  if (!result.ok()) return Result<std::string>::fail(result.error);

  return Result<std::string>::success(std::move(result.value.first));
}

// =============================================================================
// Solana Message Signing
// =============================================================================

Result<ByteVector> signSolanaMessage(const ByteVector& message, const Bytes32& private_key) {
  auto sig = ed25519Sign(message, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  return Result<ByteVector>::success(ByteVector(sig.value.data.begin(), sig.value.data.end()));
}

Result<ByteVector> signSolanaMessage(const std::string& message, const Bytes32& private_key) {
  ByteVector msg(message.begin(), message.end());
  return signSolanaMessage(msg, private_key);
}

Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  Ed25519Signature sig;
  std::copy(signature.begin(), signature.end(), sig.data.begin());

  return ed25519Verify(message, sig, public_key);
}

Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const std::string& address
) {
  auto pubkey = solanaAddressToPublicKey(address);
  if (!pubkey.ok()) {
    return Result<bool>::fail(pubkey.error);
  }

  return verifySolanaMessage(message, signature, pubkey.value);
}

// =============================================================================
// Solana Off-Chain Message Signing
// =============================================================================

Result<ByteVector> signOffChainMessage(const std::string& message, const Bytes32& private_key) {
  // Format: "\x00solana offchain\n" + message
  ByteVector to_sign;
  const char* prefix = "\x00solana offchain\n";
  to_sign.insert(to_sign.end(), prefix, prefix + 18);
  to_sign.insert(to_sign.end(), message.begin(), message.end());

  return signSolanaMessage(to_sign, private_key);
}

Result<bool> verifyOffChainMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
) {
  ByteVector to_verify;
  const char* prefix = "\x00solana offchain\n";
  to_verify.insert(to_verify.end(), prefix, prefix + 18);
  to_verify.insert(to_verify.end(), message.begin(), message.end());

  return verifySolanaMessage(to_verify, signature, address);
}

// =============================================================================
// Solana Transaction Signing
// =============================================================================

Result<ByteVector> signTransaction(const ByteVector& message_bytes, const Bytes32& private_key) {
  // For Solana transactions, we sign the message bytes directly
  // (they're already the serialized message that's signed)
  return signSolanaMessage(message_bytes, private_key);
}

Result<bool> verifyTransactionSignature(
  const ByteVector& message_bytes,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  return verifySolanaMessage(message_bytes, signature, public_key);
}

// =============================================================================
// Solana Key Derivation
// =============================================================================

Result<std::pair<Bytes32, Bytes32>> deriveKeypair(const Bytes32& seed) {
  // For Ed25519, the seed IS the private key
  // Derive public key from it
  auto pubkey = derivePublicKey(seed);
  if (!pubkey.ok()) {
    return Result<std::pair<Bytes32, Bytes32>>::fail(pubkey.error);
  }

  return Result<std::pair<Bytes32, Bytes32>>::success(
    std::make_pair(seed, pubkey.value)
  );
}

Result<Bytes32> derivePublicKey(const Bytes32& private_key) {
  return ed25519PublicKey(private_key);
}

// =============================================================================
// Solana Coin Implementation
// =============================================================================

Solana::Solana(Network network)
  : network_(network) {
}

Result<std::string> Solana::addressFromPublicKey(const Bytes33& public_key) const {
  // For Solana, we expect a 32-byte Ed25519 key
  // If Bytes33 is used, take the first 32 bytes (or last 32 if first is padding)

  // Check if first byte looks like a padding byte
  Bytes32 ed_pubkey;
  if (public_key[0] == 0x00 || public_key[0] == 0x01) {
    // Assume first byte is padding/prefix, use bytes 1-32
    std::copy(public_key.begin() + 1, public_key.end(), ed_pubkey.begin());
  } else {
    // Use first 32 bytes
    std::copy(public_key.begin(), public_key.begin() + 32, ed_pubkey.begin());
  }

  return addressFromEd25519PublicKey(ed_pubkey);
}

Result<std::string> Solana::addressFromEd25519PublicKey(const Bytes32& public_key) const {
  return solanaAddress(public_key);
}

Error Solana::validateAddress(const std::string& address) const {
  return validateSolanaAddress(address, false);
}

Result<DecodedAddress> Solana::decodeAddress(const std::string& address) const {
  auto pubkey = solanaAddressToPublicKey(address);
  if (!pubkey.ok()) {
    return Result<DecodedAddress>::fail(pubkey.error);
  }

  DecodedAddress result;
  result.address = address;
  result.network = network_;
  result.version = 0;
  result.data = ByteVector(pubkey.value.begin(), pubkey.value.end());

  return Result<DecodedAddress>::success(std::move(result));
}

Result<ByteVector> Solana::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  return signSolanaMessage(message, private_key);
}

Result<bool> Solana::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  if (public_key.size() != 32) {
    return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
  }

  Bytes32 pubkey;
  std::copy(public_key.begin(), public_key.end(), pubkey.begin());

  return verifySolanaMessage(message, signature, pubkey);
}

std::string Solana::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  // Solana uses a different derivation path: m/44'/501'/account'/change'
  // Note: All levels are hardened for Ed25519
  std::ostringstream path;
  path << "m/44'/501'/" << account << "'/" << change << "'";
  return path.str();
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 32 || !address_out || address_size < 44) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  auto result = solanaAddress(pubkey);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_validate_address(const char* address) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(validateSolanaAddress(address, false));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address_to_pubkey(
  const char* address,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!address || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = solanaAddressToPublicKey(address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(message, message + message_len);
  auto result = signSolanaMessage(msg, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
) {
  if (!message || !signature || signature_len != 64 || !public_key || pubkey_len != 32) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  ByteVector msg(message, message + message_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = verifySolanaMessage(msg, sig, pubkey);
  if (!result.ok()) return -static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_derive_pubkey(
  const uint8_t* private_key,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!private_key || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = derivePublicKey(priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_find_pda(
  const uint8_t* program_id,
  const uint8_t* seeds,
  size_t seeds_len,
  const size_t* seed_lengths,
  size_t num_seeds,
  char* address_out,
  size_t address_size,
  uint8_t* bump_out
) {
  if (!program_id || !address_out || address_size < 44 || !bump_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 prog;
  std::copy(program_id, program_id + 32, prog.begin());

  // Solana allows at most 16 seeds of at most 32 bytes each; the lengths must
  // add up to exactly seeds_len (no seed read past the buffer).
  if (num_seeds > 16 || (num_seeds > 0 && !seed_lengths) || (seeds_len > 0 && !seeds)) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  size_t total = 0;
  for (size_t i = 0; i < num_seeds; i++) {
    if (seed_lengths[i] > 32) {
      return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    total += seed_lengths[i];
  }
  if (total != seeds_len) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::vector<ByteVector> seed_vec;
  size_t offset = 0;
  for (size_t i = 0; i < num_seeds; i++) {
    seed_vec.emplace_back(seeds + offset, seeds + offset + seed_lengths[i]);
    offset += seed_lengths[i];
  }

  auto result = findProgramAddress(prog, seed_vec);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.first.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.first.c_str());
  *bump_out = result.value.second;
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_get_associated_token_address(
  const char* wallet_address,
  const char* mint_address,
  char* address_out,
  size_t address_size
) {
  if (!wallet_address || !mint_address || !address_out || address_size < 44) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = getAssociatedTokenAddress(wallet_address, mint_address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
