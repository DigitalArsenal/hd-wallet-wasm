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
#include "hd_wallet/tx/bitcoin_tx.h"
#include "hd_wallet/tx/ethereum_tx.h"

#include <array>
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
