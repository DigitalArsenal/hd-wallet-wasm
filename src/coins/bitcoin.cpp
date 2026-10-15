/**
 * @file bitcoin.cpp
 * @brief Bitcoin Support Implementation
 */

#include "hd_wallet/coins/bitcoin.h"
#include "../key_validation.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/oids.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Bitcoin Network Parameters
// =============================================================================

const BitcoinParams BITCOIN_MAINNET = {
  .p2pkh_version = 0x00,
  .p2sh_version = 0x05,
  .bech32_hrp = "bc",
  .wif_version = 0x80,
  .xprv_version = 0x0488ADE4,
  .xpub_version = 0x0488B21E,
  .yprv_version = 0x049D7878,
  .ypub_version = 0x049D7CB2,
  .zprv_version = 0x04B2430C,
  .zpub_version = 0x04B24746
};

const BitcoinParams BITCOIN_TESTNET = {
  .p2pkh_version = 0x6F,
  .p2sh_version = 0xC4,
  .bech32_hrp = "tb",
  .wif_version = 0xEF,
  .xprv_version = 0x04358394,
  .xpub_version = 0x043587CF,
  .yprv_version = 0x044A4E28,
  .ypub_version = 0x044A5262,
  .zprv_version = 0x045F18BC,
  .zpub_version = 0x045F1CF6
};

// =============================================================================
// Bitcoin Address Generation
// =============================================================================

Result<std::string> bitcoinP2PKH(const ByteVector& public_key, const BitcoinParams& params) {
  if (public_key.size() != 33 && public_key.size() != 65) {
    return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
  }

  // Hash160 of public key
  ByteVector hash = hash160(public_key);

  // Add version byte
  ByteVector versioned;
  versioned.push_back(params.p2pkh_version);
  versioned.insert(versioned.end(), hash.begin(), hash.end());

  // Base58Check encode
  return Result<std::string>::success(base58CheckEncode(versioned));
}

Result<std::string> bitcoinP2SH(const Bytes33& public_key, const BitcoinParams& params) {
  // Create P2SH-P2WPKH address (wrapped SegWit)
  // Redeem script: 0x00 0x14 <20-byte-pubkey-hash>

  // Hash160 of public key
  ByteVector pubkey_hash = hash160(public_key.data(), public_key.size());

  // Create redeem script
  ByteVector redeem_script;
  redeem_script.push_back(0x00);  // OP_0
  redeem_script.push_back(0x14);  // Push 20 bytes
  redeem_script.insert(redeem_script.end(), pubkey_hash.begin(), pubkey_hash.end());

  return bitcoinP2SHFromScript(redeem_script, params);
}

Result<std::string> bitcoinP2SHFromScript(const ByteVector& redeem_script, const BitcoinParams& params) {
  // Hash160 of redeem script
  ByteVector script_hash = hash160(redeem_script);

  // Add version byte
  ByteVector versioned;
  versioned.push_back(params.p2sh_version);
  versioned.insert(versioned.end(), script_hash.begin(), script_hash.end());

  // Base58Check encode
  return Result<std::string>::success(base58CheckEncode(versioned));
}

Result<std::string> bitcoinP2WPKH(const Bytes33& public_key, const BitcoinParams& params) {
  // Native SegWit v0 (witness version 0, 20-byte pubkey hash)

  // Hash160 of public key
  ByteVector pubkey_hash = hash160(public_key.data(), public_key.size());

  // Bech32 encode with witness version 0
  std::string address = bech32Encode(params.bech32_hrp, pubkey_hash, 0);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<std::string> bitcoinP2WSH(const ByteVector& witness_script, const BitcoinParams& params) {
  // Native SegWit v0 (witness version 0, 32-byte script hash)

  // SHA256 of witness script
  CryptoPP::SHA256 sha256;
  ByteVector script_hash(32);
  sha256.CalculateDigest(script_hash.data(), witness_script.data(), witness_script.size());

  // Bech32 encode with witness version 0
  std::string address = bech32Encode(params.bech32_hrp, script_hash, 0);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<std::string> bitcoinP2TR(const ByteVector& public_key, const BitcoinParams& params) {
  // Taproot (witness version 1, 32-byte tweaked public key)

  Bytes32 x_only;

  if (public_key.size() == 32) {
    // Already x-only format
    std::copy(public_key.begin(), public_key.end(), x_only.begin());
  } else if (public_key.size() == 33) {
    // Compressed public key - extract x coordinate
    Bytes33 compressed;
    std::copy(public_key.begin(), public_key.end(), compressed.begin());
    auto result = toXOnlyPublicKey(compressed);
    if (!result.ok()) return Result<std::string>::fail(result.error);
    x_only = result.value;
  } else {
    return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
  }

  // For a simple key-path spend with no script tree, the tweaked key is:
  // P' = P + H_taptweak(P) * G
  // where H_taptweak is tagged hash with "TapTweak"
  //
  // For simplicity, we'll just use the x-only key directly here.
  // A full implementation would apply the BIP-341 tweak.

  ByteVector x_only_vec(x_only.begin(), x_only.end());

  // Bech32m encode with witness version 1
  std::string address = bech32mEncode(params.bech32_hrp, x_only_vec, 1);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<Bytes32> toXOnlyPublicKey(const Bytes33& public_key) {
  // X-only public key is just the x coordinate (bytes 1-32 of compressed key)
  // If the y coordinate is odd (prefix 0x03), we need to negate to get even y
  // But for Taproot, we just take the x coordinate as-is

  Bytes32 result;
  std::copy(public_key.begin() + 1, public_key.end(), result.begin());
  return Result<Bytes32>::success(std::move(result));
}

// =============================================================================
// Bitcoin Address Validation
// =============================================================================

namespace {

// The one reading of an address this wallet pays to: its type and payload
// (the 20-byte hash of P2PKH, P2SH and P2WPKH; the 32-byte program of P2WSH
// and P2TR). A SegWit address is typed by its witness version and program
// length together (BIP-141, BIP-350): v0/20 P2WPKH, v0/32 P2WSH, v1/32 P2TR.
// Every other address is refused, never mapped to a script it does not encode.
struct BitcoinPayee {
  BitcoinAddressType type;
  ByteVector payload;
};

// The parameters of a network id at the C ABI: 0 mainnet, 1 testnet. Any
// other id (regtest included: its bech32 HRP is bcrt) is refused, never read
// as testnet.
const BitcoinParams* bitcoinNetworkParams(int32_t network) {
  if (network == 0) return &BITCOIN_MAINNET;
  if (network == 1) return &BITCOIN_TESTNET;
  return nullptr;
}

Result<BitcoinPayee> decodeBitcoinPayee(const std::string& address, const BitcoinParams& params) {
  using R = Result<BitcoinPayee>;
  if (address.empty()) {
    return R::fail(Error::INVALID_ADDRESS);
  }

  std::string lower_address = address;
  std::transform(lower_address.begin(), lower_address.end(), lower_address.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  if (lower_address.rfind(std::string(params.bech32_hrp) + "1", 0) == 0) {
    auto decoded = decodeSegwitAddress(address);
    if (!decoded.ok() || decoded.value.hrp != params.bech32_hrp) {
      return R::fail(Error::INVALID_ADDRESS);
    }
    const uint8_t version = decoded.value.witness_version;
    const size_t length = decoded.value.program.size();
    BitcoinAddressType type;
    if (version == 0 && length == 20) {
      type = BitcoinAddressType::P2WPKH;
    } else if (version == 0 && length == 32) {
      type = BitcoinAddressType::P2WSH;
    } else if (version == 1 && length == 32) {
      type = BitcoinAddressType::P2TR;
    } else {
      return R::fail(Error::INVALID_ADDRESS);
    }
    return R::success(BitcoinPayee{type, std::move(decoded.value.program)});
  }

  // Base58Check: one version byte and a 20-byte hash.
  auto decoded = base58CheckDecode(address);
  if (!decoded.ok() || decoded.value.size() != 21) {
    return R::fail(Error::INVALID_ADDRESS);
  }
  BitcoinAddressType type;
  if (decoded.value[0] == params.p2pkh_version) {
    type = BitcoinAddressType::P2PKH;
  } else if (decoded.value[0] == params.p2sh_version) {
    type = BitcoinAddressType::P2SH;
  } else {
    return R::fail(Error::INVALID_ADDRESS);
  }
  return R::success(BitcoinPayee{type, ByteVector(decoded.value.begin() + 1, decoded.value.end())});
}

Result<void> validateAs(const std::string& address, const BitcoinParams& params, BitcoinAddressType type) {
  auto payee = decodeBitcoinPayee(address, params);
  if (!payee.ok()) {
    return Result<void>::fail(payee.error);
  }
  if (payee.value.type != type) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }
  return Result<void>::success();
}

}  // namespace

Result<BitcoinAddressType> detectBitcoinAddressType(
  const std::string& address,
  const BitcoinParams& params
) {
  auto payee = decodeBitcoinPayee(address, params);
  if (!payee.ok()) {
    return Result<BitcoinAddressType>::fail(payee.error);
  }
  return Result<BitcoinAddressType>::success(BitcoinAddressType{payee.value.type});
}

Result<void> validateP2PKH(const std::string& address, const BitcoinParams& params) {
  return validateAs(address, params, BitcoinAddressType::P2PKH);
}

Result<void> validateP2SH(const std::string& address, const BitcoinParams& params) {
  return validateAs(address, params, BitcoinAddressType::P2SH);
}

Result<void> validateP2WPKH(const std::string& address, const BitcoinParams& params) {
  return validateAs(address, params, BitcoinAddressType::P2WPKH);
}

Result<void> validateP2WSH(const std::string& address, const BitcoinParams& params) {
  return validateAs(address, params, BitcoinAddressType::P2WSH);
}

Result<void> validateP2TR(const std::string& address, const BitcoinParams& params) {
  return validateAs(address, params, BitcoinAddressType::P2TR);
}

Result<void> validateBitcoinAddress(const std::string& address, const BitcoinParams& params) {
  auto payee = decodeBitcoinPayee(address, params);
  return payee.ok() ? Result<void>::success() : Result<void>::fail(payee.error);
}

Result<ByteVector> decodeToScriptPubKey(const std::string& address, const BitcoinParams& params) {
  auto payee = decodeBitcoinPayee(address, params);
  if (!payee.ok()) {
    return Result<ByteVector>::fail(payee.error);
  }
  const ByteVector& payload = payee.value.payload;

  ByteVector script;
  switch (payee.value.type) {
    case BitcoinAddressType::P2PKH:
      // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      script = {0x76, 0xA9, 0x14};
      script.insert(script.end(), payload.begin(), payload.end());
      script.push_back(0x88);
      script.push_back(0xAC);
      break;
    case BitcoinAddressType::P2SH:
      // OP_HASH160 <20 bytes> OP_EQUAL
      script = {0xA9, 0x14};
      script.insert(script.end(), payload.begin(), payload.end());
      script.push_back(0x87);
      break;
    case BitcoinAddressType::P2WPKH:
      // OP_0 <20 bytes>
      script = {0x00, 0x14};
      script.insert(script.end(), payload.begin(), payload.end());
      break;
    case BitcoinAddressType::P2WSH:
      // OP_0 <32 bytes>
      script = {0x00, 0x20};
      script.insert(script.end(), payload.begin(), payload.end());
      break;
    case BitcoinAddressType::P2TR:
      // OP_1 <32 bytes>
      script = {0x51, 0x20};
      script.insert(script.end(), payload.begin(), payload.end());
      break;
    default:
      return Result<ByteVector>::fail(Error::INVALID_ADDRESS);
  }

  return Result<ByteVector>::success(std::move(script));
}

// =============================================================================
// Bitcoin Message Signing
// =============================================================================

Bytes32 bitcoinMessageHash(const std::string& message) {
  // Bitcoin signed message format:
  // "\x18Bitcoin Signed Message:\n" + varint(len) + message

  ByteVector to_sign;

  // Magic prefix
  const char* magic = "\x18" "Bitcoin Signed Message:\n";
  to_sign.insert(to_sign.end(), magic, magic + 25);

  // Varint message length
  size_t len = message.size();
  if (len < 0xFD) {
    to_sign.push_back(static_cast<uint8_t>(len));
  } else if (len <= 0xFFFF) {
    to_sign.push_back(0xFD);
    to_sign.push_back(len & 0xFF);
    to_sign.push_back((len >> 8) & 0xFF);
  } else {
    to_sign.push_back(0xFE);
    to_sign.push_back(len & 0xFF);
    to_sign.push_back((len >> 8) & 0xFF);
    to_sign.push_back((len >> 16) & 0xFF);
    to_sign.push_back((len >> 24) & 0xFF);
  }

  // Message
  to_sign.insert(to_sign.end(), message.begin(), message.end());

  // Double SHA256
  return doubleSha256(to_sign);
}

Result<ByteVector> signBitcoinMessage(
  const std::string& message,
  const Bytes32& private_key,
  bool compressed
) {
  // Hash the message
  Bytes32 hash = bitcoinMessageHash(message);

  // Sign with ECDSA
  auto sig = ecdsaSign(hash, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  // Create 65-byte signature
  // Format: 1 byte header + 32 bytes r + 32 bytes s
  // Header: 27 + recovery_id + (compressed ? 4 : 0)

  ByteVector result(65);
  uint8_t header = 27 + sig.value.v;
  if (compressed) header += 4;

  result[0] = header;
  std::copy(sig.value.r.begin(), sig.value.r.end(), result.begin() + 1);
  std::copy(sig.value.s.begin(), sig.value.s.end(), result.begin() + 33);

  return Result<ByteVector>::success(std::move(result));
}

Result<bool> verifyBitcoinMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address,
  const BitcoinParams& params
) {
  // Recover public key from signature
  auto recovered = recoverBitcoinMessageSigner(message, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  // Generate address from recovered public key
  auto addr_result = bitcoinP2PKH(recovered.value, params);
  if (!addr_result.ok()) {
    return Result<bool>::fail(addr_result.error);
  }

  // Compare addresses
  return Result<bool>::success(addr_result.value == address);
}

Result<ByteVector> recoverBitcoinMessageSigner(
  const std::string& message,
  const ByteVector& signature
) {
  if (signature.size() != 65) {
    return Result<ByteVector>::fail(Error::INVALID_SIGNATURE);
  }

  // Parse signature header
  uint8_t header = signature[0];
  if (header < 27 || header > 34) {
    return Result<ByteVector>::fail(Error::INVALID_SIGNATURE);
  }

  bool compressed = (header >= 31);
  uint8_t recovery_id = (header - 27) % 4;

  // Extract r and s
  ECDSASignature sig;
  std::copy(signature.begin() + 1, signature.begin() + 33, sig.r.begin());
  std::copy(signature.begin() + 33, signature.end(), sig.s.begin());
  sig.v = recovery_id;

  // Hash the message
  Bytes32 hash = bitcoinMessageHash(message);

  // Recover public key
  auto recovered = ecdsaRecover(hash, sig);
  if (!recovered.ok()) {
    return Result<ByteVector>::fail(recovered.error);
  }

  if (compressed) {
    return Result<ByteVector>::success(ByteVector(recovered.value.begin(), recovered.value.end()));
  } else {
    // Decompress
    auto uncompressed = bip32::decompressPublicKey(recovered.value, Curve::SECP256K1);
    if (!uncompressed.ok()) {
      return Result<ByteVector>::fail(uncompressed.error);
    }
    return Result<ByteVector>::success(ByteVector(uncompressed.value.begin(), uncompressed.value.end()));
  }
}

// =============================================================================
// WIF (Wallet Import Format)
// =============================================================================

std::string toWIF(const Bytes32& private_key, bool compressed, const BitcoinParams& params) {
  ByteVector data;
  data.push_back(params.wif_version);
  data.insert(data.end(), private_key.begin(), private_key.end());

  if (compressed) {
    data.push_back(0x01);
  }

  return base58CheckEncode(data);
}

Result<std::pair<Bytes32, bool>> fromWIF(const std::string& wif) {
  auto decoded = base58CheckDecode(wif);
  if (!decoded.ok()) {
    return Result<std::pair<Bytes32, bool>>::fail(decoded.error);
  }

  // Check length (version + 32 bytes key + optional compression flag)
  if (decoded.value.size() != 33 && decoded.value.size() != 34) {
    return Result<std::pair<Bytes32, bool>>::fail(Error::INVALID_ARGUMENT);
  }

  bool compressed = (decoded.value.size() == 34);

  Bytes32 private_key;
  std::copy(decoded.value.begin() + 1, decoded.value.begin() + 33, private_key.begin());

  return Result<std::pair<Bytes32, bool>>::success(std::make_pair(std::move(private_key), compressed));
}

// =============================================================================
// Bitcoin Coin Implementation
// =============================================================================

Bitcoin::Bitcoin(Network network)
  : network_(network),
    params_(network == Network::MAINNET ? &BITCOIN_MAINNET : &BITCOIN_TESTNET),
    address_type_(BitcoinAddressType::P2WPKH) {
}

void Bitcoin::setNetwork(Network net) {
  network_ = net;
  params_ = (net == Network::MAINNET) ? &BITCOIN_MAINNET : &BITCOIN_TESTNET;
}

Result<std::string> Bitcoin::addressFromPublicKey(const Bytes33& public_key) const {
  switch (address_type_) {
    case BitcoinAddressType::P2PKH:
      return p2pkhAddress(public_key);
    case BitcoinAddressType::P2SH:
      return p2shAddress(public_key);
    case BitcoinAddressType::P2WPKH:
      return p2wpkhAddress(public_key);
    case BitcoinAddressType::P2TR:
      return p2trAddress(public_key);
    default:
      return p2wpkhAddress(public_key);
  }
}

Result<std::string> Bitcoin::addressFromPublicKeyUncompressed(const Bytes65& public_key) const {
  // For P2PKH, we can use uncompressed keys
  if (address_type_ == BitcoinAddressType::P2PKH) {
    ByteVector pubkey(public_key.begin(), public_key.end());
    return bitcoinP2PKH(pubkey, *params_);
  }

  // Other types require compressed keys
  auto compressed = bip32::compressPublicKey(public_key, Curve::SECP256K1);
  if (!compressed.ok()) {
    return Result<std::string>::fail(compressed.error);
  }
  return addressFromPublicKey(compressed.value);
}

Result<std::string> Bitcoin::p2pkhAddress(const Bytes33& public_key) const {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return bitcoinP2PKH(pubkey, *params_);
}

Result<std::string> Bitcoin::p2shAddress(const Bytes33& public_key) const {
  return bitcoinP2SH(public_key, *params_);
}

Result<std::string> Bitcoin::p2wpkhAddress(const Bytes33& public_key) const {
  return bitcoinP2WPKH(public_key, *params_);
}

Result<std::string> Bitcoin::p2wshAddress(const ByteVector& witness_script) const {
  return bitcoinP2WSH(witness_script, *params_);
}

Result<std::string> Bitcoin::p2trAddress(const Bytes33& public_key) const {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return bitcoinP2TR(pubkey, *params_);
}

Error Bitcoin::validateAddress(const std::string& address) const {
  auto result = validateBitcoinAddress(address, *params_);
  return result.ok() ? Error::OK : result.error;
}

Result<DecodedAddress> Bitcoin::decodeAddress(const std::string& address) const {
  auto payee = decodeBitcoinPayee(address, *params_);
  if (!payee.ok()) {
    return Result<DecodedAddress>::fail(payee.error);
  }

  DecodedAddress decoded;
  decoded.address = address;
  decoded.network = network_;
  switch (payee.value.type) {
    case BitcoinAddressType::P2PKH: decoded.version = params_->p2pkh_version; break;
    case BitcoinAddressType::P2SH:  decoded.version = params_->p2sh_version; break;
    case BitcoinAddressType::P2TR:  decoded.version = 1; break;
    default:                        decoded.version = 0; break;  // P2WPKH, P2WSH
  }
  decoded.data = std::move(payee.value.payload);
  return Result<DecodedAddress>::success(std::move(decoded));
}

Result<BitcoinAddressType> Bitcoin::detectAddressType(const std::string& address) const {
  return detectBitcoinAddressType(address, *params_);
}

Result<ByteVector> Bitcoin::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  std::string msg_str(message.begin(), message.end());
  return signBitcoinMessage(msg_str, private_key, true);
}

Result<bool> Bitcoin::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  // Recover and compare public keys
  std::string msg_str(message.begin(), message.end());
  auto recovered = recoverBitcoinMessageSigner(msg_str, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  // Compare public keys
  bool match = (recovered.value.size() == public_key.size() &&
                std::equal(recovered.value.begin(), recovered.value.end(), public_key.begin()));

  return Result<bool>::success(std::move(match));
}

std::string Bitcoin::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  std::ostringstream path;
  path << "m/" << defaultPurpose() << "'/"
       << static_cast<uint32_t>(CoinType::BITCOIN) << "'/"
       << account << "'/"
       << change << "/"
       << index;
  return path.str();
}

uint32_t Bitcoin::defaultPurpose() const {
  switch (address_type_) {
    case BitcoinAddressType::P2PKH:
      return 44;
    case BitcoinAddressType::P2SH:
      return 49;
    case BitcoinAddressType::P2WPKH:
    case BitcoinAddressType::P2WSH:
      return 84;
    case BitcoinAddressType::P2TR:
      return 86;
    default:
      return 84;
  }
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2pkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  ByteVector pubkey(public_key, public_key + pubkey_len);

  auto result = bitcoinP2PKH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2sh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 33 || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = bitcoinP2SH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wpkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 33 || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = bitcoinP2WPKH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wsh_address(
  const uint8_t* witness_script,
  size_t script_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!witness_script || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  ByteVector script(witness_script, witness_script + script_len);

  auto result = bitcoinP2WSH(script, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2tr_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  ByteVector pubkey(public_key, public_key + pubkey_len);

  auto result = bitcoinP2TR(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_validate_address(const char* address, int32_t network) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  auto result = validateBitcoinAddress(address, params);
  return static_cast<int32_t>(result.error);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_detect_address_type(const char* address, int32_t network) {
  if (!address) {
    return -1;
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return -1;
  }
  const BitcoinParams& params = *network_params;
  auto result = detectBitcoinAddressType(address, params);
  if (!result.ok()) return -1;

  return static_cast<int32_t>(result.value);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_decode_address(
  const char* address,
  int32_t* type_out,
  uint8_t* hash_out,
  size_t* hash_len,
  int32_t* network_out
) {
  if (!address || !type_out || !hash_out || !hash_len || !network_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  // The network is the one whose HRP or version bytes the address decodes
  // under (they differ, so at most one does).
  const std::string addr(address);
  Network net = Network::MAINNET;
  auto payee = decodeBitcoinPayee(addr, BITCOIN_MAINNET);
  if (!payee.ok()) {
    net = Network::TESTNET;
    payee = decodeBitcoinPayee(addr, BITCOIN_TESTNET);
  }
  if (!payee.ok()) {
    return static_cast<int32_t>(payee.error);
  }
  const ByteVector& payload = payee.value.payload;

  if (payload.size() > *hash_len) {
    *hash_len = payload.size();
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(payload.begin(), payload.end(), hash_out);
  *hash_len = payload.size();
  *type_out = static_cast<int32_t>(payee.value.type);
  *network_out = static_cast<int32_t>(net);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_sign_message(
  const char* message,
  const uint8_t* private_key,
  int32_t compressed,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = signBitcoinMessage(message, priv, compressed != 0);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_verify_message(
  const char* message,
  const uint8_t* signature,
  size_t signature_len,
  const char* address,
  int32_t network
) {
  if (!message || !signature || signature_len != 65 || !address) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  ByteVector sig(signature, signature + signature_len);

  auto result = verifyBitcoinMessage(message, sig, address, params);
  if (!result.ok()) return -static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_to_wif(
  const uint8_t* private_key,
  int32_t compressed,
  int32_t network,
  char* wif_out,
  size_t wif_size
) {
  if (!private_key || !wif_out || wif_size < 52) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  // Only a secp256k1 scalar 0 < d < n is a private key.
  if (!keys::isValidPrivateKey(Curve::SECP256K1, private_key, 32)) {
    std::memset(wif_out, 0, wif_size);
    return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
  }

  const BitcoinParams* network_params = bitcoinNetworkParams(network);
  if (!network_params) {
    std::memset(wif_out, 0, wif_size);
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const BitcoinParams& params = *network_params;
  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  std::string wif = toWIF(priv, compressed != 0, params);
  // Safe string copy with bounds checking (need space for null terminator)
  if (wif.size() + 1 > wif_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(wif_out, wif.c_str(), wif.size());
  wif_out[wif.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_from_wif(
  const char* wif,
  uint8_t* private_key_out,
  int32_t* compressed_out
) {
  if (!wif || !private_key_out || !compressed_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = fromWIF(wif);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.first.begin(), result.value.first.end(), private_key_out);
  *compressed_out = result.value.second ? 1 : 0;
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
