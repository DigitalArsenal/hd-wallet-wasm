/**
 * @file test_tx_signing.cpp
 * @brief Transaction and coin ECDSA signing against published vectors
 *
 * Each protocol digest (BIP-143 sighash, EIP-155 Keccak-256 signing hash) is
 * signed as given: RFC 6979 deterministic k, low-S, strict DER for Bitcoin and
 * the recovery id in Ethereum's v. A signer that hashes the digest again
 * cannot reproduce these bytes.
 *
 * Vectors:
 * - BIP-143 "Native P2WPKH" example, input 1 (published sighash and signature;
 *   dcrd's RFC 6979 signer reproduces the same DER).
 * - EIP-155 example transaction (nonce 9, recovery id 0, v = 37).
 * - The same transaction at nonce 0 (recovery id 1, v = 38), produced
 *   independently with dcrd secp256k1 SignCompact and a hand-written RLP
 *   encoder that reproduces the EIP-155 example byte for byte.
 */

#include "test_framework.h"
#include "hd_wallet/types.h"
#include "hd_wallet/coins/coin.h"
#include "hd_wallet/coins/ethereum.h"
#include "hd_wallet/tx/bitcoin_tx.h"
#include "hd_wallet/tx/ethereum_tx.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace hd_wallet;

namespace {

std::string toHex(const uint8_t* data, size_t len) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0f]);
  }
  return out;
}

template <typename Container>
std::string toHex(const Container& bytes) {
  return toHex(bytes.data(), bytes.size());
}

// BIP-143 native P2WPKH example (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
const char* kBip143UnsignedTx =
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff"
    "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206"
    "000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42db"
    "ee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const char* kBip143PrivateKey = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const char* kBip143PublicKey = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
const char* kBip143SigHash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
const char* kBip143Signature =
    "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561"
    "406f90300e8f3358f51928d43c212a8caed02de67eebee01";

// EIP-155 example (https://eips.ethereum.org/EIPS/eip-155).
const char* kEip155PrivateKey = "4646464646464646464646464646464646464646464646464646464646464646";
const char* kEip155SignedNonce9 =
    "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef6134"
    "0bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3"
    "dc64214b297fb1966a3b6d83";
const char* kEip155SignedNonce0 =
    "f86c808504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008026a0f3d5a389"
    "0fbcbd1f1f7c9affab932af4062e4f03e3ac8cea31ed36f705390da6a03cef06a6742d436a0c36ac89ca98197d44e12292"
    "5ce59947d398172d97ce41cb";

tx::EthereumTransaction eip155Example(uint64_t nonce) {
  tx::EthereumTransaction transaction(1);
  transaction.setNonce(nonce);
  transaction.setGasPrice(20000000000ULL);
  transaction.setGasLimit(21000);
  transaction.setTo(test::hexToArray<20>("3535353535353535353535353535353535353535"));
  transaction.setValue(1000000000000000000ULL);
  return transaction;
}

}  // namespace

TEST_CASE(TxSigning, Bip143NativeP2wpkhSignatureMatchesPublishedVector) {
  auto parsed = tx::BitcoinTransaction::parseHex(kBip143UnsignedTx);
  ASSERT_OK(parsed);
  tx::BitcoinTransaction transaction = std::move(parsed.value);
  ASSERT_EQ(static_cast<size_t>(2), transaction.inputCount());

  tx::TxInput& input = transaction.getInput(1);
  input.amount = 600000000ULL;  // 6 BTC
  input.scriptType = tx::ScriptType::P2WPKH;

  const auto priv = test::hexToArray<32>(kBip143PrivateKey);
  ASSERT_TRUE(Error::OK == transaction.signInput(1, priv, tx::SigHashType::ALL));

  const tx::TxInput& signedInput = transaction.getInput(1);
  ASSERT_EQ(static_cast<size_t>(2), signedInput.witness.size());
  ASSERT_STR_EQ(kBip143Signature, toHex(signedInput.witness[0]));
  ASSERT_STR_EQ(kBip143PublicKey, toHex(signedInput.witness[1]));
}

TEST_CASE(TxSigning, CoinEcdsaSignsTheDigestAsGiven) {
  const auto hash = test::hexToArray<32>(kBip143SigHash);
  const auto priv = test::hexToArray<32>(kBip143PrivateKey);

  auto signature = coins::ecdsaSign(hash, priv);
  ASSERT_OK(signature);
  // DER of the published BIP-143 signature without its sighash-type byte.
  std::string expectedDer(kBip143Signature);
  expectedDer.resize(expectedDer.size() - 2);
  ASSERT_STR_EQ(expectedDer, toHex(signature.value.toDER()));

  const auto pub = test::hexToBytes(kBip143PublicKey);
  auto valid = coins::ecdsaVerify(hash, signature.value, ByteVector(pub.begin(), pub.end()));
  ASSERT_OK(valid);
  ASSERT_TRUE(valid.value);

  auto recovered = coins::ecdsaRecover(hash, signature.value);
  ASSERT_OK(recovered);
  ASSERT_STR_EQ(kBip143PublicKey, toHex(recovered.value));

}

TEST_CASE(TxSigning, Eip155LegacyRecoveryIdZero) {
  auto transaction = eip155Example(9);
  ASSERT_TRUE(Error::OK == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));
  ASSERT_EQ(static_cast<uint64_t>(37), transaction.signatureV());
  auto serialized = transaction.serialize();
  ASSERT_OK(serialized);
  ASSERT_STR_EQ(kEip155SignedNonce9, toHex(serialized.value));
}

TEST_CASE(TxSigning, Eip155LegacyRecoveryIdOne) {
  auto transaction = eip155Example(0);
  ASSERT_TRUE(Error::OK == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));
  ASSERT_EQ(static_cast<uint64_t>(38), transaction.signatureV());
  auto serialized = transaction.serialize();
  ASSERT_OK(serialized);
  ASSERT_STR_EQ(kEip155SignedNonce0, toHex(serialized.value));
}

// =============================================================================
// Ethereum recipient and value (2.1.1)
// =============================================================================
//
// A transaction whose recipient never parsed used to serialize and sign with
// to = 0x00..00 (isContractCreation_ stays false), sending the value to the
// burn address. A transfer now needs a recipient; only an explicit contract
// creation has none.

namespace {

const char* const kBadRecipients[] = {
    "vitalik.eth",                                    // ENS name
    "0x52908400098527886E0F7030069857D2E4169EE",      // 39 hex digits
    "0x52908400098527886E0F7030069857D2E4169EE7a",    // 41 hex digits
    "0x52908400098527886E0F7030069857D2E4169EE7x",    // extra character
    "0x52908400098527886E0F7030069857D2E4169EEg",     // 40 chars, one not hex
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",     // Bitcoin address
    "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV",    // Solana address
    "",
    // A second prefix: hexToBytes stripped it again, leaving 19 bytes and an
    // uninitialized last byte that was signed as the recipient's.
    "0x0x52908400098527886E0F7030069857D2E4169E",
    "0X0x52908400098527886E0F7030069857D2E4169E",
    "0x0X52908400098527886E0F7030069857D2E4169E",
    "0x",
    " 0x52908400098527886E0F7030069857D2E4169EE7",    // leading space
    "0x52908400098527886E0F7030069857D2E4169EE7\n",   // trailing newline
    "0x52908400098527886E0F7030069857D2E4169EE7 ",    // trailing space
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",     // EIP-55 checksum broken (last d)
    "0x0000000000000000000000000000000000000000",     // zero address: only a contract creation has no recipient
    "0000000000000000000000000000000000000000",
};

tx::EthereumTransaction eip1559Transfer() {
  auto transaction = tx::EthereumTransaction::createEIP1559(1, 2000000000ULL, 30000000000ULL);
  transaction.setNonce(7);
  transaction.setGasLimit(21000);
  return transaction;
}

}  // namespace

TEST_CASE(TxSigning, EthTransferWithoutRecipientDoesNotSerializeOrSign) {
  for (auto transaction : {tx::EthereumTransaction(1), eip1559Transfer()}) {
    transaction.setValue(1000000000000000000ULL);
    ASSERT_FALSE(transaction.hasRecipient());
    ASSERT_ERROR(transaction.serialize(), Error::INVALID_ADDRESS);
    ASSERT_ERROR(transaction.serializeForSigning(), Error::INVALID_ADDRESS);
    ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.validate());
    ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));
    ASSERT_FALSE(transaction.hasSignature());
  }
}

TEST_CASE(TxSigning, EthUnparsableRecipientIsRefusedAndLeavesNoRecipient) {
  for (const char* recipient : kBadRecipients) {
    auto transaction = eip1559Transfer();
    transaction.setValue(1000000000000000000ULL);
    ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.setToFromHex(recipient));
    ASSERT_FALSE(transaction.hasRecipient());
    ASSERT_ERROR(transaction.serialize(), Error::INVALID_ADDRESS);
    ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));

    // The C API used by the WASM wrapper: the setter reports the error and
    // the transaction still cannot be serialized.
    tx::eth_tx_handle handle = tx::hd_eth_tx_create_eip1559(1, 2000000000ULL, 30000000000ULL);
    ASSERT_TRUE(handle != nullptr);
    tx::hd_eth_tx_set_gas_limit(handle, 21000);
    tx::hd_eth_tx_set_value(handle, 1000000000000000000ULL);
    ASSERT_EQ(static_cast<int32_t>(Error::INVALID_ADDRESS), tx::hd_eth_tx_set_to_hex(handle, recipient));
    uint8_t out[512];
    size_t outLen = 0;
    ASSERT_EQ(static_cast<int32_t>(Error::INVALID_ADDRESS), tx::hd_eth_tx_serialize(handle, out, sizeof(out), &outLen));
    const auto key = test::hexToArray<32>(kEip155PrivateKey);
    ASSERT_EQ(static_cast<int32_t>(Error::INVALID_ADDRESS), tx::hd_eth_tx_sign(handle, key.data()));
    tx::hd_eth_tx_destroy(handle);
  }
}

TEST_CASE(TxSigning, EthExplicitContractCreationSerializesWithEmptyTo) {
  auto transaction = eip1559Transfer();
  transaction.setContractCreation(true);
  transaction.setData(ByteVector{0x60, 0x00});
  ASSERT_TRUE(transaction.hasRecipient());
  ASSERT_TRUE(Error::OK == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));
  auto serialized = transaction.serialize();
  ASSERT_OK(serialized);
  auto parsed = tx::EthereumTransaction::parse(serialized.value);
  ASSERT_OK(parsed);
  ASSERT_TRUE(parsed.value.isContractCreation());
}

TEST_CASE(TxSigning, EthParseRefusesMalformedRecipientField) {
  // The EIP-155 example with a 19-byte 'to' field: neither a recipient nor a
  // contract creation (it used to parse as a contract creation).
  std::string hex(kEip155SignedNonce9);
  std::string recipient = "94";
  for (int i = 0; i < 20; ++i) recipient += "35";
  std::string shortRecipient = "93";
  for (int i = 0; i < 19; ++i) shortRecipient += "35";
  const size_t at = hex.find(recipient);
  ASSERT_TRUE(at != std::string::npos);
  hex.replace(at, recipient.size(), shortRecipient);
  ASSERT_STR_EQ("f86c", hex.substr(0, 4));
  hex.replace(0, 4, "f86b");
  auto parsed = tx::EthereumTransaction::parseHex(hex);
  ASSERT_ERROR(parsed, Error::INVALID_TRANSACTION);

  // The unmodified transaction still parses with its recipient.
  auto original = tx::EthereumTransaction::parseHex(kEip155SignedNonce9);
  ASSERT_OK(original);
  ASSERT_TRUE(original.value.hasRecipient());
  ASSERT_FALSE(original.value.isContractCreation());
  auto reserialized = original.value.serialize();
  ASSERT_OK(reserialized);
  ASSERT_STR_EQ(kEip155SignedNonce9, toHex(reserialized.value));
}

TEST_CASE(TxSigning, EthValueAboveTwoToThe64SerializesInFull) {
  // 20 ETH = 20 * 10^18 wei = 0x01158e460913d00000, above 2^64 - 1.
  auto transaction = eip1559Transfer();
  ASSERT_TRUE(Error::OK == transaction.setToFromHex("0x52908400098527886E0F7030069857D2E4169EE7"));
  Bytes32 twentyEth{};
  const auto valueBytes = test::hexToBytes("01158e460913d00000");
  std::copy(valueBytes.begin(), valueBytes.end(), twentyEth.end() - valueBytes.size());
  transaction.setValue(twentyEth);
  auto serialized = transaction.serialize();
  ASSERT_OK(serialized);
  // RLP of the value: 0x89 (9-byte string) then the nine bytes.
  ASSERT_TRUE(toHex(serialized.value).find("94" "52908400098527886e0f7030069857d2e4169ee7" "89" "01158e460913d00000") !=
              std::string::npos);
  auto parsed = tx::EthereumTransaction::parse(serialized.value);
  ASSERT_OK(parsed);
  ASSERT_STR_EQ(toHex(twentyEth), toHex(parsed.value.value()));

  // Through the C API's 256-bit setter, which the WASM wrapper now uses.
  tx::eth_tx_handle handle = tx::hd_eth_tx_create_eip1559(1, 2000000000ULL, 30000000000ULL);
  ASSERT_TRUE(handle != nullptr);
  tx::hd_eth_tx_set_nonce(handle, 7);
  tx::hd_eth_tx_set_gas_limit(handle, 21000);
  ASSERT_EQ(0, tx::hd_eth_tx_set_to_hex(handle, "0x52908400098527886E0F7030069857D2E4169EE7"));
  tx::hd_eth_tx_set_value_256(handle, twentyEth.data());
  uint8_t out[512];
  size_t outLen = 0;
  ASSERT_EQ(0, tx::hd_eth_tx_serialize(handle, out, sizeof(out), &outLen));
  ASSERT_STR_EQ(toHex(serialized.value), toHex(out, outLen));
  tx::hd_eth_tx_destroy(handle);
}

// =============================================================================
// Recipient parsing (2.1.1 round 2): the only accepted form
// =============================================================================
//
// A recipient is exactly 40 ASCII hex digits after at most one 0x/0X prefix;
// mixed case must be its EIP-55 checksum; the zero address is refused (a
// transaction without a recipient is an explicit contract creation). These
// tests check the setter, parseAddress and the C API against a reference
// written here, over hand-picked and generated inputs.

namespace {

// EIP-55's published examples: checksummed form.
const char* const kChecksummed[] = {
    "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
};

std::string lowerAscii(std::string s) {
  for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

bool isHexAscii(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// The reference rule. `known` maps a lowercase body to its EIP-55 form for
// deciding mixed-case inputs; a mixed-case body not in it is a broken checksum.
bool referenceAccepts(const std::string& input, std::string* bodyOut) {
  size_t start = 0;
  if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) start = 2;
  if (input.size() - start != 40) return false;
  std::string body = input.substr(start);
  bool lower = false, upper = false, nonZero = false;
  for (char c : body) {
    if (!isHexAscii(c)) return false;
    if (c >= 'a' && c <= 'f') lower = true;
    if (c >= 'A' && c <= 'F') upper = true;
    if (c != '0') nonZero = true;
  }
  if (!nonZero) return false;
  if (lower && upper) {
    bool matches = false;
    for (const char* known : kChecksummed) matches |= (body == known);
    if (!matches) return false;
  }
  if (bodyOut) *bodyOut = lowerAscii(body);
  return true;
}

// Checks one input through every entry point; returns "" or a description.
std::string checkRecipient(const std::string& input) {
  std::string body;
  const bool expected = referenceAccepts(input, &body);

  auto transaction = tx::EthereumTransaction::createEIP1559(1, 1, 2);
  // A good recipient first: a refused one must clear it, not keep it.
  transaction.setToFromHex("0x52908400098527886E0F7030069857D2E4169EE7");
  const Error err = transaction.setToFromHex(input);
  const bool accepted = err == Error::OK;
  std::string escaped;
  for (unsigned char c : input) {
    if (c >= 0x20 && c < 0x7f) escaped.push_back(static_cast<char>(c));
    else { char buf[8]; std::snprintf(buf, sizeof(buf), "\\x%02x", c); escaped += buf; }
  }
  if (accepted != expected) {
    return "setToFromHex(\"" + escaped + "\") " + (accepted ? "accepted" : "refused") +
           ", expected " + (expected ? "accept" : "refuse");
  }
  if (transaction.hasRecipient() != expected) return "hasRecipient wrong for \"" + escaped + "\"";
  if (!expected && err != Error::INVALID_ADDRESS) return "wrong error for \"" + escaped + "\"";
  if (expected && toHex(transaction.to().data(), 20) != body) return "wrong bytes for \"" + escaped + "\"";
  if (!expected && transaction.serialize().ok()) return "serialized without a recipient: \"" + escaped + "\"";

  // parseAddress agrees on shape (it does not refuse the zero address).
  auto parsed = tx::parseAddress(input);
  bool parseExpected = expected;
  if (!expected) {
    std::string zeroBody;
    size_t start = (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) ? 2 : 0;
    parseExpected = input.size() - start == 40 && input.find_first_not_of('0', start) == std::string::npos;
  }
  if (parsed.ok() != parseExpected) return "parseAddress disagrees on \"" + escaped + "\"";

  // The address validator a UI checks first never passes what parseAddress
  // refuses or reads differently (it may be stricter: it wants an EIP-55
  // checksum or lowercase 0x form).
  if (coins::validateEthereumAddress(input) == Error::OK) {
    if (!parsed.ok()) return "validateEthereumAddress passes what parseAddress refuses: \"" + escaped + "\"";
    std::string lower = lowerAscii(input.substr(input.size() - 40));
    if (toHex(parsed.value.data(), 20) != lower) return "validator and parser read different bytes";
  }

  // The C API reads a C string: only inputs without a NUL reach it intact.
  if (input.find('\0') == std::string::npos) {
    tx::eth_tx_handle handle = tx::hd_eth_tx_create_eip1559(1, 1, 2);
    const int32_t rc = tx::hd_eth_tx_set_to_hex(handle, input.c_str());
    tx::hd_eth_tx_destroy(handle);
    if ((rc == 0) != expected) return "hd_eth_tx_set_to_hex disagrees on \"" + escaped + "\"";
    uint8_t out[20];
    std::memset(out, 0xa5, sizeof(out));
    const int32_t prc = tx::hd_eth_parse_address(input.c_str(), out);
    if ((prc == 0) != parseExpected) return "hd_eth_parse_address disagrees on \"" + escaped + "\"";
    if (prc == 0 && expected && toHex(out, 20) != body) return "hd_eth_parse_address bytes wrong";
  }
  return "";
}

struct Fuzz {
  uint64_t state;
  uint32_t next() {
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return static_cast<uint32_t>(state >> 16);
  }
  size_t below(size_t n) { return next() % n; }
};

// Pieces an address could be confused with: ASCII hex, prefixes, whitespace,
// NUL, other scripts' digits, look-alike letters, invisible characters.
const char* const kPieces[] = {
    "0", "1", "7", "9", "a", "f", "A", "F", "e", "E", "0x", "0X", "x", "X", "g", "G", "-", "+",
    " ", "\t", "\n", "\r", "" /* NUL, see piece() */,
    "\xef\xbc\x90",      // FULLWIDTH DIGIT ZERO
    "\xef\xbc\x91",      // FULLWIDTH DIGIT ONE
    "\xef\xbd\x81",      // FULLWIDTH LATIN SMALL LETTER A
    "\xd9\xa3",          // ARABIC-INDIC DIGIT THREE
    "\xe0\xa5\xab",      // DEVANAGARI DIGIT FIVE
    "\xc2\xb2",          // SUPERSCRIPT TWO
    "\xc2\xa0",          // NO-BREAK SPACE
    "\xe2\x80\x8b",      // ZERO WIDTH SPACE
    "\xef\xbb\xbf",      // BYTE ORDER MARK
    "\xd0\x90",          // CYRILLIC CAPITAL A
    "\xd1\x81",          // CYRILLIC SMALL ES (looks like c)
};

std::string piece(size_t i) {
  // The NUL piece must keep its length (a C string literal would lose it).
  if (std::strcmp(kPieces[i], "") == 0) return std::string("\0", 1);
  return kPieces[i];
}

}  // namespace

TEST_CASE(TxSigning, EthRecipientAcceptsOnlyFortyHexDigitsAfterOnePrefix) {
  // Hand-picked accepts and refusals.
  const char* const accepted[] = {
      "0x52908400098527886E0F7030069857D2E4169EE7",
      "0X52908400098527886E0F7030069857D2E4169EE7",
      "52908400098527886e0f7030069857d2e4169ee7",
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
      "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
      "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
      "0x0000000000000000000000000000000000000001",
  };
  for (const char* a : accepted) ASSERT_STR_EQ("", checkRecipient(a));
  for (const char* b : kBadRecipients) {
    ASSERT_FALSE(referenceAccepts(b, nullptr));
    ASSERT_STR_EQ("", checkRecipient(b));
  }
  // A NUL inside the string (a std::string can carry one).
  ASSERT_STR_EQ("", checkRecipient(std::string("0x52908400098527886E0F7030069857D2E4169EE7\0", 43)));
  ASSERT_STR_EQ("", checkRecipient(std::string("0x52908400098527886E0F7030069857D2E4169E\0\0", 42)));
}

TEST_CASE(TxSigning, EthRecipientFuzzPrefixesWhitespaceUnicodeLengths) {
  const std::string valid = "52908400098527886e0f7030069857d2e4169ee7";
  const char* const prefixes[] = {"", "0x", "0X", "0x0x", "0X0x", "0x0X", "00x", "x", "0", "0xx", " 0x",
                                  "0x ", "\t0x", "+0x", "-0x", "\xef\xbc\x90x", "0\xef\xbd\x98", "\xef\xbb\xbf" "0x"};
  const char* const suffixes[] = {"", " ", "\n", "\r\n", "\t", "\xc2\xa0", "\xe2\x80\x8b", "0", "00"};
  size_t cases = 0;
  size_t mismatches = 0;
  std::string first;
  auto run = [&](const std::string& input) {
    ++cases;
    std::string problem = checkRecipient(input);
    if (!problem.empty()) {
      ++mismatches;
      if (first.empty()) first = problem;
    }
  };

  // Every prefix x body length 36..44 x suffix (bodies cut from or padded to
  // a valid address, plus each EIP-55 example and its case variants).
  std::vector<std::string> bodies;
  for (size_t len = 36; len <= 44; ++len) {
    std::string body = valid;
    while (body.size() < len) body += "a";
    bodies.push_back(body.substr(0, len));
  }
  for (const char* known : kChecksummed) {
    bodies.push_back(known);
    bodies.push_back(lowerAscii(known));
    std::string upper = known;
    for (auto& c : upper) if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
    bodies.push_back(upper);
  }
  for (const char* prefix : prefixes) {
    for (const auto& body : bodies) {
      for (const char* suffix : suffixes) run(std::string(prefix) + body + suffix);
      run(std::string(prefix) + body + std::string("\0", 1));
    }
  }

  // One edit of each checksummed address: delete, case flip, and insert or
  // replace with every piece, at every position.
  for (const char* known : kChecksummed) {
    const std::string base = std::string("0x") + known;
    for (size_t at = 0; at <= base.size(); ++at) {
      if (at < base.size()) {
        run(base.substr(0, at) + base.substr(at + 1));
        std::string flipped = base;
        char& c = flipped[at];
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        else if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        run(flipped);
      }
      for (size_t p = 0; p < sizeof(kPieces) / sizeof(kPieces[0]); ++p) {
        run(base.substr(0, at) + piece(p) + base.substr(at));
        if (at < base.size()) run(base.substr(0, at) + piece(p) + base.substr(at + 1));
      }
    }
  }

  // Random strings of pieces, lengths 0..48 pieces, half with a 0x prefix;
  // and random lowercase-hex strings of 0..50 digits (some of them valid).
  Fuzz fuzz{0x9e3779b97f4a7c15ULL};
  for (int i = 0; i < 20000; ++i) {
    std::string s = (fuzz.next() & 1) ? "0x" : "";
    const size_t n = fuzz.below(49);
    for (size_t k = 0; k < n; ++k) s += piece(fuzz.below(sizeof(kPieces) / sizeof(kPieces[0])));
    run(s);
  }
  for (int i = 0; i < 20000; ++i) {
    std::string s = (fuzz.next() & 1) ? "0x" : "";
    const size_t n = (fuzz.next() & 3) ? 40 : fuzz.below(51);
    for (size_t k = 0; k < n; ++k) s.push_back("0123456789abcdef"[fuzz.below(16)]);
    run(s);
  }

  ASSERT_TRUE(cases > 50000);
  ASSERT_STR_EQ("", first);
  ASSERT_EQ(static_cast<size_t>(0), mismatches);
}

TEST_CASE(TxSigning, EthZeroAddressOnlyAsExplicitContractCreation) {
  const std::array<uint8_t, 20> zero{};
  auto transaction = eip1559Transfer();
  transaction.setValue(1000000000000000000ULL);
  ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.setTo(zero));
  ASSERT_FALSE(transaction.hasRecipient());
  ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.sign(test::hexToArray<32>(kEip155PrivateKey)));

  // A refused recipient also undoes an earlier one and an earlier contract creation.
  ASSERT_TRUE(Error::OK == transaction.setTo(test::hexToArray<20>("3535353535353535353535353535353535353535")));
  ASSERT_TRUE(transaction.hasRecipient());
  ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.setTo(zero));
  ASSERT_FALSE(transaction.hasRecipient());
  transaction.setContractCreation(true);
  ASSERT_TRUE(Error::INVALID_ADDRESS == transaction.setToFromHex("0x0x52908400098527886E0F7030069857D2E4169E"));
  ASSERT_FALSE(transaction.isContractCreation());
  ASSERT_FALSE(transaction.hasRecipient());

  // The C API's byte setter.
  tx::eth_tx_handle handle = tx::hd_eth_tx_create_eip1559(1, 2000000000ULL, 30000000000ULL);
  ASSERT_EQ(static_cast<int32_t>(Error::INVALID_ADDRESS), tx::hd_eth_tx_set_to(handle, zero.data()));
  uint8_t out[512];
  size_t outLen = 0;
  ASSERT_EQ(static_cast<int32_t>(Error::INVALID_ADDRESS), tx::hd_eth_tx_serialize(handle, out, sizeof(out), &outLen));
  tx::hd_eth_tx_destroy(handle);

  // Contract creation clears a recipient set before it and serializes an empty 'to'.
  auto creation = eip1559Transfer();
  ASSERT_TRUE(Error::OK == creation.setToFromHex("0x52908400098527886E0F7030069857D2E4169EE7"));
  creation.setContractCreation(true);
  ASSERT_TRUE(creation.hasRecipient());
  ASSERT_TRUE(creation.isContractCreation());
  auto serialized = creation.serialize();
  ASSERT_OK(serialized);
  ASSERT_TRUE(toHex(serialized.value).find("52908400098527886e0f7030069857d2e4169ee7") == std::string::npos);
}

TEST_CASE(TxSigning, EthAddressFromPublicKeyRefusesNonPoints) {
  // Private key 1: the generator's address.
  const std::string expected = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
  const auto compressed = test::hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  const auto uncompressed = test::hexToBytes(
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  uint8_t out[20];
  ASSERT_EQ(0, tx::hd_eth_pubkey_to_address(compressed.data(), compressed.size(), out));
  ASSERT_STR_EQ(expected, toHex(out, 20));  // used to be 0x00..00
  ASSERT_EQ(0, tx::hd_eth_pubkey_to_address(uncompressed.data(), uncompressed.size(), out));
  ASSERT_STR_EQ(expected, toHex(out, 20));

  auto badPrefix = uncompressed;
  badPrefix[0] = 0x00;
  auto offCurve = uncompressed;
  offCurve[64] ^= 0x01;
  auto badCompressed = compressed;
  badCompressed[0] = 0x05;
  std::vector<uint8_t> noX(33, 0xff);
  noX[0] = 0x02;
  for (const auto* key : {&badPrefix, &offCurve, &badCompressed, &noX}) {
    std::memset(out, 0xa5, sizeof(out));
    ASSERT_EQ(static_cast<int32_t>(Error::INVALID_PUBLIC_KEY),
              tx::hd_eth_pubkey_to_address(key->data(), key->size(), out));
    ASSERT_STR_EQ("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", toHex(out, 20));  // output untouched
  }
}
