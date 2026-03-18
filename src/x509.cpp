/**
 * @file x509.cpp
 * @brief OpenSSL-backed X.509 support
 */

#include "hd_wallet/x509.h"

#include "hd_wallet/ecdsa.h"
#include "hd_wallet/eddsa.h"
#include "hd_wallet/error.h"
#include "hd_wallet/utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if HD_WALLET_USE_OPENSSL
#include "hd_wallet/crypto_openssl.h"

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#endif

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace hd_wallet {
namespace x509 {

#if HD_WALLET_USE_OPENSSL
namespace {

template <typename T, auto FreeFn>
using UniqueOsslPtr = std::unique_ptr<T, decltype(FreeFn)>;

using UniqueBio = UniqueOsslPtr<BIO, &BIO_free>;
using UniqueX509 = UniqueOsslPtr<X509, &X509_free>;
using UniqueX509Ext = UniqueOsslPtr<X509_EXTENSION, &X509_EXTENSION_free>;
using UniqueX509Name = UniqueOsslPtr<X509_NAME, &X509_NAME_free>;
using UniqueEvpPkey = UniqueOsslPtr<EVP_PKEY, &EVP_PKEY_free>;
using UniqueEvpPkeyCtx = UniqueOsslPtr<EVP_PKEY_CTX, &EVP_PKEY_CTX_free>;
using UniqueMd = UniqueOsslPtr<EVP_MD, &EVP_MD_free>;
using UniqueBn = UniqueOsslPtr<BIGNUM, &BN_clear_free>;
using UniqueParamBld = UniqueOsslPtr<OSSL_PARAM_BLD, &OSSL_PARAM_BLD_free>;
using UniqueParams = UniqueOsslPtr<OSSL_PARAM, &OSSL_PARAM_free>;
using UniquePkcs12 = UniqueOsslPtr<PKCS12, &PKCS12_free>;
using UniqueAsn1Ia5 = UniqueOsslPtr<ASN1_IA5STRING, &ASN1_IA5STRING_free>;
using UniqueEcGroup = UniqueOsslPtr<EC_GROUP, &EC_GROUP_free>;
using UniqueEcPoint = UniqueOsslPtr<EC_POINT, &EC_POINT_free>;

struct CurveProfile {
  Curve curve;
  int nid;
  const char* group_name;
  const char* digest_name;
  size_t private_key_size;
  bool certificate_curve;
  bool signing_curve;
  bool fips_approved;
};

const CurveProfile* findCurveProfile(Curve curve) {
  static constexpr CurveProfile kProfiles[] = {
      {Curve::SECP256K1, NID_secp256k1, "secp256k1", "SHA256", 32, false, true, false},
      {Curve::ED25519, NID_undef, "ED25519", "none", 32, false, true, false},
      {Curve::P256, NID_X9_62_prime256v1, "P-256", "SHA256", 32, true, true, true},
      {Curve::P384, NID_secp384r1, "P-384", "SHA384", 48, true, true, true},
      {Curve::X25519, NID_undef, "X25519", "none", 32, false, false, false},
  };

  for (const auto& profile : kProfiles) {
    if (profile.curve == curve) {
      return &profile;
    }
  }
  return nullptr;
}

Error bufferTooSmall(size_t required, size_t* actual) {
  if (actual != nullptr) {
    *actual = required;
  }
  return Error::OUT_OF_MEMORY;
}

int32_t writeBytesToOutput(const ByteVector& data, uint8_t* output, size_t* output_len) {
  if (output_len == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  if (output == nullptr) {
    *output_len = data.size();
    return 0;
  }
  if (*output_len < data.size()) {
    return -static_cast<int32_t>(bufferTooSmall(data.size(), output_len));
  }
  std::memcpy(output, data.data(), data.size());
  *output_len = data.size();
  return 0;
}

int32_t writeStringToOutput(const std::string& data, char* output, size_t* output_len) {
  if (output_len == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const size_t required = data.size() + 1;
  if (output == nullptr) {
    *output_len = required;
    return 0;
  }
  if (*output_len < required) {
    return -static_cast<int32_t>(bufferTooSmall(required, output_len));
  }
  std::memcpy(output, data.c_str(), required);
  *output_len = required;
  return 0;
}

std::string trim(const std::string& input) {
  size_t start = 0;
  while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
    ++start;
  }
  size_t end = input.size();
  while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
    --end;
  }
  return input.substr(start, end - start);
}

std::vector<std::string> splitEscaped(const std::string& input, char delimiter) {
  std::vector<std::string> parts;
  std::string current;
  bool escaped = false;

  for (char ch : input) {
    if (escaped) {
      current.push_back(ch);
      escaped = false;
      continue;
    }
    if (ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == delimiter) {
      auto value = trim(current);
      if (!value.empty()) {
        parts.push_back(value);
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }

  auto value = trim(current);
  if (!value.empty()) {
    parts.push_back(value);
  }
  return parts;
}

std::string join(const std::vector<std::string>& values, const std::string& separator) {
  std::ostringstream oss;
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      oss << separator;
    }
    oss << values[i];
  }
  return oss.str();
}

bool parseBool(const std::string& value) {
  const std::string lowered = [&]() {
    std::string tmp = trim(value);
    std::transform(tmp.begin(), tmp.end(), tmp.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    return tmp;
  }();
  return lowered == "1" || lowered == "true" || lowered == "yes";
}

std::string jsonEscape(const std::string& input) {
  std::ostringstream oss;
  for (unsigned char ch : input) {
    switch (ch) {
      case '\\': oss << "\\\\"; break;
      case '"': oss << "\\\""; break;
      case '\b': oss << "\\b"; break;
      case '\f': oss << "\\f"; break;
      case '\n': oss << "\\n"; break;
      case '\r': oss << "\\r"; break;
      case '\t': oss << "\\t"; break;
      default:
        if (ch < 0x20) {
          oss << "\\u"
              << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(ch)
              << std::dec << std::setfill(' ');
        } else {
          oss << static_cast<char>(ch);
        }
    }
  }
  return oss.str();
}

std::string jsonString(const std::string& value) {
  return "\"" + jsonEscape(value) + "\"";
}

std::string hexEncode(const uint8_t* data, size_t length, bool uppercase = false) {
  static constexpr char kHexLower[] = "0123456789abcdef";
  static constexpr char kHexUpper[] = "0123456789ABCDEF";
  const char* alphabet = uppercase ? kHexUpper : kHexLower;
  std::string out;
  out.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    out.push_back(alphabet[data[i] >> 4]);
    out.push_back(alphabet[data[i] & 0x0F]);
  }
  return out;
}

std::string hexEncode(const ByteVector& data, bool uppercase = false) {
  return hexEncode(data.data(), data.size(), uppercase);
}

Result<ByteVector> hexDecode(const std::string& input) {
  size_t start = 0;
  if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
    start = 2;
  }
  if (((input.size() - start) % 2) != 0) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }
  ByteVector out;
  out.reserve((input.size() - start) / 2);
  auto toNibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
  };
  for (size_t i = start; i < input.size(); i += 2) {
    const int hi = toNibble(input[i]);
    const int lo = toNibble(input[i + 1]);
    if (hi < 0 || lo < 0) {
      return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return Result<ByteVector>::success(std::move(out));
}

ByteVector serialBytes(const ASN1_INTEGER* serial) {
  if (serial == nullptr) {
    return {};
  }
  const unsigned char* data = ASN1_STRING_get0_data(reinterpret_cast<const ASN1_STRING*>(serial));
  const int length = ASN1_STRING_length(reinterpret_cast<const ASN1_STRING*>(serial));
  if (data == nullptr || length <= 0) {
    return {};
  }
  return ByteVector(data, data + length);
}

std::string serialHex(X509* certificate) {
  return hexEncode(serialBytes(X509_get0_serialNumber(certificate)), true);
}

Result<X509_NAME*> parseDistinguishedName(const std::string& dn) {
  UniqueX509Name name(X509_NAME_new(), X509_NAME_free);
  if (!name) {
    return Result<X509_NAME*>::fail(Error::OUT_OF_MEMORY);
  }

  const auto rdns = splitEscaped(dn, ',');
  for (const auto& rdn : rdns) {
    const auto pos = rdn.find('=');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= rdn.size()) {
      return Result<X509_NAME*>::fail(Error::INVALID_ARGUMENT);
    }
    const std::string field = trim(rdn.substr(0, pos));
    const std::string value = trim(rdn.substr(pos + 1));
    if (field.empty() || value.empty()) {
      return Result<X509_NAME*>::fail(Error::INVALID_ARGUMENT);
    }
    if (X509_NAME_add_entry_by_txt(
            name.get(),
            field.c_str(),
            MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            static_cast<int>(value.size()),
            -1,
            0) != 1) {
      return Result<X509_NAME*>::fail(Error::INVALID_ARGUMENT);
    }
  }

  return Result<X509_NAME*>::success(name.release());
}

std::string x509NameToString(X509_NAME* name) {
  if (name == nullptr) {
    return "";
  }
  UniqueBio bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio) {
    return "";
  }
  X509_NAME_print_ex(
      bio.get(),
      name,
      0,
      XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  if (mem == nullptr || mem->data == nullptr || mem->length == 0) {
    return "";
  }
  return std::string(mem->data, mem->length);
}

std::string asn1TimeToString(const ASN1_TIME* time) {
  if (time == nullptr) {
    return "";
  }
  struct tm tm_value {};
  if (ASN1_TIME_to_tm(time, &tm_value) != 1) {
    return "";
  }
  std::ostringstream oss;
  oss << std::put_time(&tm_value, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

ByteVector digestSha256(const uint8_t* data, size_t length) {
  ByteVector out(SHA256_DIGEST_LENGTH);
  SHA256(data, length, out.data());
  return out;
}

ByteVector digestSha384(const uint8_t* data, size_t length) {
  ByteVector out(SHA384_DIGEST_LENGTH);
  SHA384(data, length, out.data());
  return out;
}

ByteVector certificateSpkiDigest(X509* certificate) {
  int encoded_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), nullptr);
  if (encoded_len <= 0) {
    return {};
  }
  ByteVector encoded(static_cast<size_t>(encoded_len));
  unsigned char* cursor = encoded.data();
  i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &cursor);
  return digestSha256(encoded.data(), encoded.size());
}

Result<EVP_PKEY*> makeEcPrivateKey(Curve curve, const ByteVector& private_key) {
  const auto* profile = findCurveProfile(curve);
  if (profile == nullptr || profile->nid == NID_undef) {
    return Result<EVP_PKEY*>::fail(Error::NOT_SUPPORTED);
  }
  if (private_key.size() != profile->private_key_size) {
    return Result<EVP_PKEY*>::fail(Error::INVALID_PRIVATE_KEY);
  }

  UniqueBn priv_bn(BN_bin2bn(private_key.data(), static_cast<int>(private_key.size()), nullptr), BN_clear_free);
  UniqueEcGroup group(EC_GROUP_new_by_curve_name(profile->nid), EC_GROUP_free);
  if (!priv_bn || !group) {
    return Result<EVP_PKEY*>::fail(Error::OUT_OF_MEMORY);
  }
  UniqueEcPoint pub_key(EC_POINT_new(group.get()), EC_POINT_free);
  if (!pub_key) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }
  if (EC_POINT_mul(group.get(), pub_key.get(), priv_bn.get(), nullptr, nullptr, nullptr) != 1) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }

  const size_t public_key_len = EC_POINT_point2oct(
      group.get(), pub_key.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (public_key_len == 0) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }
  ByteVector public_key(public_key_len);
  if (EC_POINT_point2oct(
          group.get(),
          pub_key.get(),
          POINT_CONVERSION_UNCOMPRESSED,
          public_key.data(),
          public_key.size(),
          nullptr) != public_key.size()) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }

  UniqueEvpPkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return Result<EVP_PKEY*>::fail(Error::OUT_OF_MEMORY);
  }
  if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }

  UniqueParamBld param_bld(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!param_bld) {
    return Result<EVP_PKEY*>::fail(Error::OUT_OF_MEMORY);
  }
  if (OSSL_PARAM_BLD_push_utf8_string(
          param_bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, profile->group_name, 0) != 1 ||
      OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv_bn.get()) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(
          param_bld.get(), OSSL_PKEY_PARAM_PUB_KEY, public_key.data(), public_key.size()) != 1) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }
  UniqueParams params(OSSL_PARAM_BLD_to_param(param_bld.get()), OSSL_PARAM_free);
  if (!params) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) != 1 || key == nullptr) {
    return Result<EVP_PKEY*>::fail(Error::INTERNAL);
  }

  return Result<EVP_PKEY*>::success(std::move(key));
}

Result<ByteVector> deriveWalletPublicKey(Curve curve, const ByteVector& private_key) {
  const auto* profile = findCurveProfile(curve);
  if (profile == nullptr || !profile->signing_curve) {
    return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }

  switch (curve) {
    case Curve::SECP256K1: {
#if HD_WALLET_USE_CRYPTOPP
      CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey priv;
      CryptoPP::Integer d(private_key.data(), private_key.size());
      priv.Initialize(CryptoPP::ASN1::secp256k1(), d);
      CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pub;
      priv.MakePublicKey(pub);
      const auto& point = pub.GetPublicElement();
      ByteVector out(33);
      out[0] = point.y.IsOdd() ? 0x03 : 0x02;
      point.x.Encode(out.data() + 1, 32);
      return Result<ByteVector>::success(std::move(out));
#else
      return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
    }
    case Curve::P256:
    case Curve::P384: {
      auto evp_result = makeEcPrivateKey(curve, private_key);
      if (!evp_result.ok()) {
        return Result<ByteVector>::fail(evp_result.error);
      }
      UniqueEvpPkey key(evp_result.value, EVP_PKEY_free);
      size_t required = 0;
      if (EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &required) != 1) {
        return Result<ByteVector>::fail(Error::INTERNAL);
      }
      ByteVector out(required);
      if (EVP_PKEY_get_octet_string_param(
              key.get(), OSSL_PKEY_PARAM_PUB_KEY, out.data(), out.size(), &required) != 1) {
        return Result<ByteVector>::fail(Error::INTERNAL);
      }
      out.resize(required);
      return Result<ByteVector>::success(std::move(out));
    }
    case Curve::ED25519: {
      if (private_key.size() != eddsa::ED25519_SEED_SIZE) {
        return Result<ByteVector>::fail(Error::INVALID_PRIVATE_KEY);
      }
      ByteVector out(eddsa::ED25519_PUBLIC_KEY_SIZE);
      const int32_t rc = eddsa::hd_ed25519_pubkey_from_seed(private_key.data(), out.data(), out.size());
      if (rc != 0) {
        return Result<ByteVector>::fail(static_cast<Error>(rc < 0 ? -rc : rc));
      }
      return Result<ByteVector>::success(std::move(out));
    }
    case Curve::X25519:
      return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }

  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
}

Result<ByteVector> signWalletPayload(
    Curve curve,
    const ByteVector& private_key,
    const ByteVector& payload) {
  switch (curve) {
    case Curve::SECP256K1: {
      if (private_key.size() != 32) {
        return Result<ByteVector>::fail(Error::INVALID_PRIVATE_KEY);
      }
      Bytes32 priv {};
      std::memcpy(priv.data(), private_key.data(), private_key.size());
      const auto digest = digestSha256(payload.data(), payload.size());
      Bytes32 hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      auto sig = ecdsa::secp256k1Sign(priv, hash);
      if (!sig.ok()) {
        return Result<ByteVector>::fail(sig.error);
      }
      return Result<ByteVector>::success(ByteVector(sig.value.begin(), sig.value.end()));
    }
    case Curve::P256: {
      if (private_key.size() != 32) {
        return Result<ByteVector>::fail(Error::INVALID_PRIVATE_KEY);
      }
      Bytes32 priv {};
      std::memcpy(priv.data(), private_key.data(), private_key.size());
      const auto digest = digestSha256(payload.data(), payload.size());
      Bytes32 hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      auto sig = ecdsa::p256Sign(priv, hash);
      if (!sig.ok()) {
        return Result<ByteVector>::fail(sig.error);
      }
      return Result<ByteVector>::success(ByteVector(sig.value.begin(), sig.value.end()));
    }
    case Curve::P384: {
      if (private_key.size() != 48) {
        return Result<ByteVector>::fail(Error::INVALID_PRIVATE_KEY);
      }
      ecdsa::P384PrivateKey priv {};
      std::memcpy(priv.data(), private_key.data(), private_key.size());
      const auto digest = digestSha384(payload.data(), payload.size());
      std::array<uint8_t, 48> hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      auto sig = ecdsa::p384Sign(priv, hash);
      if (!sig.ok()) {
        return Result<ByteVector>::fail(sig.error);
      }
      return Result<ByteVector>::success(ByteVector(sig.value.begin(), sig.value.end()));
    }
    case Curve::ED25519: {
      if (private_key.size() != eddsa::ED25519_SEED_SIZE) {
        return Result<ByteVector>::fail(Error::INVALID_PRIVATE_KEY);
      }
      eddsa::Ed25519Seed seed {};
      std::memcpy(seed.data(), private_key.data(), private_key.size());
      auto signature = eddsa::ed25519Sign(seed, payload);
      return Result<ByteVector>::success(ByteVector(signature.begin(), signature.end()));
    }
    case Curve::X25519:
      return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }

  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
}

bool verifyWalletSignature(
    Curve curve,
    const ByteVector& public_key,
    const ByteVector& payload,
    const ByteVector& signature) {
  switch (curve) {
    case Curve::SECP256K1: {
      if (signature.size() != 64) {
        return false;
      }
      const auto digest = digestSha256(payload.data(), payload.size());
      Bytes32 hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      ecdsa::CompactSignature sig {};
      std::memcpy(sig.data(), signature.data(), sig.size());
      return ecdsa::secp256k1Verify(public_key, hash, sig);
    }
    case Curve::P256: {
      if (signature.size() != 64) {
        return false;
      }
      const auto digest = digestSha256(payload.data(), payload.size());
      Bytes32 hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      ecdsa::CompactSignature sig {};
      std::memcpy(sig.data(), signature.data(), sig.size());
      return ecdsa::p256Verify(public_key, hash, sig);
    }
    case Curve::P384: {
      if (signature.size() != 96) {
        return false;
      }
      const auto digest = digestSha384(payload.data(), payload.size());
      std::array<uint8_t, 48> hash {};
      std::memcpy(hash.data(), digest.data(), hash.size());
      ecdsa::P384Signature sig {};
      std::memcpy(sig.data(), signature.data(), sig.size());
      return ecdsa::p384Verify(public_key, hash, sig);
    }
    case Curve::ED25519: {
      if (public_key.size() != eddsa::ED25519_PUBLIC_KEY_SIZE || signature.size() != eddsa::ED25519_SIGNATURE_SIZE) {
        return false;
      }
      eddsa::Ed25519PublicKey pub {};
      eddsa::Ed25519Signature sig {};
      std::memcpy(pub.data(), public_key.data(), pub.size());
      std::memcpy(sig.data(), signature.data(), sig.size());
      return eddsa::ed25519Verify(pub, payload, sig);
    }
    case Curve::X25519:
      return false;
  }
  return false;
}

Result<std::string> buildWalletAttestationComment(
    X509* certificate,
    const WalletAttestationRequest& request) {
  const auto* profile = findCurveProfile(request.curve);
  if (profile == nullptr || !profile->signing_curve) {
    return Result<std::string>::fail(Error::NOT_SUPPORTED);
  }

  auto public_key = deriveWalletPublicKey(request.curve, request.private_key);
  if (!public_key.ok()) {
    return Result<std::string>::fail(public_key.error);
  }

  const ByteVector spki_digest = certificateSpkiDigest(certificate);
  if (spki_digest.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  std::ostringstream payload;
  payload << "version=1\n";
  payload << "serial_hex=" << serialHex(certificate) << "\n";
  payload << "issuer_dn=" << x509NameToString(X509_get_issuer_name(certificate)) << "\n";
  payload << "subject_dn=" << x509NameToString(X509_get_subject_name(certificate)) << "\n";
  payload << "not_before=" << asn1TimeToString(X509_get0_notBefore(certificate)) << "\n";
  payload << "not_after=" << asn1TimeToString(X509_get0_notAfter(certificate)) << "\n";
  payload << "subject_public_key_sha256=" << hexEncode(spki_digest, true) << "\n";

  const std::string payload_text = payload.str();
  const ByteVector payload_bytes(payload_text.begin(), payload_text.end());
  auto signature = signWalletPayload(request.curve, request.private_key, payload_bytes);
  if (!signature.ok()) {
    return Result<std::string>::fail(signature.error);
  }

  const ByteVector payload_digest = digestSha256(payload_bytes.data(), payload_bytes.size());
  std::ostringstream comment;
  comment << "{";
  comment << "\"version\":1,";
  comment << "\"proof_type\":\"wallet_binding\",";
  comment << "\"comment_prefix\":" << jsonString(request.comment_prefix) << ",";
  comment << "\"curve\":" << jsonString(curveToString(request.curve)) << ",";
  comment << "\"key_label\":" << jsonString(request.key_label) << ",";
  comment << "\"public_key_hex\":" << jsonString(hexEncode(public_key.value, true)) << ",";
  comment << "\"signature_hex\":" << jsonString(hexEncode(signature.value, true)) << ",";
  comment << "\"payload_sha256_hex\":" << jsonString(hexEncode(payload_digest, true)) << ",";
  comment << "\"signature_hash\":" << jsonString(profile->digest_name) << ",";
  comment << "\"fips_approved\":" << (profile->fips_approved ? "true" : "false");
  comment << "}";
  return Result<std::string>::success(comment.str());
}

Result<void> addCommentExtension(X509* certificate, const std::string& comment) {
  UniqueAsn1Ia5 value(ASN1_IA5STRING_new(), ASN1_IA5STRING_free);
  if (!value) {
    return Result<void>::fail(Error::OUT_OF_MEMORY);
  }
  if (ASN1_STRING_set(value.get(), comment.c_str(), static_cast<int>(comment.size())) != 1) {
    return Result<void>::fail(Error::INTERNAL);
  }

  UniqueX509Ext extension(X509V3_EXT_i2d(NID_netscape_comment, 0, value.get()), X509_EXTENSION_free);
  if (!extension) {
    return Result<void>::fail(Error::INTERNAL);
  }
  if (X509_add_ext(certificate, extension.get(), -1) != 1) {
    return Result<void>::fail(Error::INTERNAL);
  }
  return Result<void>::success();
}

Result<void> addTextExtension(X509* certificate, X509V3_CTX* ctx, int nid, const std::string& value) {
  UniqueX509Ext extension(
      X509V3_EXT_conf_nid(nullptr, ctx, nid, const_cast<char*>(value.c_str())),
      X509_EXTENSION_free);
  if (!extension) {
    return Result<void>::fail(Error::INVALID_ARGUMENT);
  }
  if (X509_add_ext(certificate, extension.get(), -1) != 1) {
    return Result<void>::fail(Error::INTERNAL);
  }
  return Result<void>::success();
}

Result<void> applyExtensions(
    X509* certificate,
    X509* issuer_certificate,
    const CertificateOptions& options) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer_certificate, certificate, nullptr, nullptr, 0);

  std::ostringstream basic_constraints;
  basic_constraints << "critical,CA:" << (options.is_ca ? "TRUE" : "FALSE");
  if (options.is_ca && options.path_len >= 0) {
    basic_constraints << ",pathlen:" << options.path_len;
  }
  auto rc = addTextExtension(certificate, &ctx, NID_basic_constraints, basic_constraints.str());
  if (!rc.ok()) {
    return rc;
  }

  std::vector<std::string> key_usage = options.key_usage;
  if (key_usage.empty()) {
    key_usage = options.is_ca
        ? std::vector<std::string>{"keyCertSign", "cRLSign"}
        : std::vector<std::string>{"digitalSignature", "keyEncipherment"};
  }
  rc = addTextExtension(certificate, &ctx, NID_key_usage, "critical," + join(key_usage, ","));
  if (!rc.ok()) {
    return rc;
  }

  if (!options.extended_key_usage.empty()) {
    rc = addTextExtension(certificate, &ctx, NID_ext_key_usage, join(options.extended_key_usage, ","));
    if (!rc.ok()) {
      return rc;
    }
  }

  std::vector<std::string> san_entries;
  for (const auto& dns : options.dns_names) {
    san_entries.push_back("DNS:" + dns);
  }
  for (const auto& ip : options.ip_addresses) {
    san_entries.push_back("IP:" + ip);
  }
  for (const auto& email : options.email_addresses) {
    san_entries.push_back("email:" + email);
  }
  for (const auto& uri : options.uri_names) {
    san_entries.push_back("URI:" + uri);
  }
  if (!san_entries.empty()) {
    rc = addTextExtension(certificate, &ctx, NID_subject_alt_name, join(san_entries, ","));
    if (!rc.ok()) {
      return rc;
    }
  }

  rc = addTextExtension(certificate, &ctx, NID_subject_key_identifier, "hash");
  if (!rc.ok()) {
    return rc;
  }

  rc = addTextExtension(
      certificate,
      &ctx,
      NID_authority_key_identifier,
      options.is_ca ? "keyid:always" : "keyid:always,issuer");
  if (!rc.ok()) {
    return rc;
  }

  return Result<void>::success();
}

Result<void> populateCertificate(
    X509* certificate,
    X509_NAME* subject_name,
    X509_NAME* issuer_name,
    EVP_PKEY* subject_key,
    const CertificateOptions& options) {
  if (X509_set_version(certificate, 2) != 1) {
    return Result<void>::fail(Error::INTERNAL);
  }

  ASN1_INTEGER* serial = X509_get_serialNumber(certificate);
  if (serial == nullptr) {
    return Result<void>::fail(Error::INTERNAL);
  }
  UniqueBn serial_bn(nullptr, BN_clear_free);
  if (!options.serial_hex.empty()) {
    BIGNUM* raw = nullptr;
    if (BN_hex2bn(&raw, options.serial_hex.c_str()) == 0 || raw == nullptr) {
      return Result<void>::fail(Error::INVALID_ARGUMENT);
    }
    serial_bn.reset(raw);
    if (BN_to_ASN1_INTEGER(serial_bn.get(), serial) == nullptr) {
      return Result<void>::fail(Error::INTERNAL);
    }
  }

  if (X509_set_subject_name(certificate, subject_name) != 1 ||
      X509_set_issuer_name(certificate, issuer_name) != 1 ||
      X509_set_pubkey(certificate, subject_key) != 1) {
    return Result<void>::fail(Error::INTERNAL);
  }

  if (ASN1_TIME_set(X509_getm_notBefore(certificate), static_cast<time_t>(options.not_before_unix)) == nullptr ||
      ASN1_TIME_set(X509_getm_notAfter(certificate), static_cast<time_t>(options.not_after_unix)) == nullptr) {
    return Result<void>::fail(Error::INTERNAL);
  }

  return Result<void>::success();
}

Result<ByteVector> encodeCertificate(X509* certificate, Encoding encoding) {
  if (encoding == Encoding::DER) {
    int len = i2d_X509(certificate, nullptr);
    if (len <= 0) {
      return Result<ByteVector>::fail(Error::INTERNAL);
    }
    ByteVector out(static_cast<size_t>(len));
    unsigned char* cursor = out.data();
    if (i2d_X509(certificate, &cursor) != len) {
      return Result<ByteVector>::fail(Error::INTERNAL);
    }
    return Result<ByteVector>::success(std::move(out));
  }

  if (encoding == Encoding::PEM) {
    UniqueBio bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1) {
      return Result<ByteVector>::fail(Error::INTERNAL);
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    if (mem == nullptr || mem->data == nullptr) {
      return Result<ByteVector>::fail(Error::INTERNAL);
    }
    return Result<ByteVector>::success(ByteVector(
        reinterpret_cast<const uint8_t*>(mem->data),
        reinterpret_cast<const uint8_t*>(mem->data) + mem->length));
  }

  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
}

Result<X509*> decodeCertificate(const ByteVector& certificate, Encoding encoding) {
  if (encoding == Encoding::DER) {
    const unsigned char* cursor = certificate.data();
    X509* parsed = d2i_X509(nullptr, &cursor, static_cast<long>(certificate.size()));
    if (parsed == nullptr) {
      return Result<X509*>::fail(Error::INVALID_ARGUMENT);
    }
    return Result<X509*>::success(std::move(parsed));
  }

  if (encoding == Encoding::PEM) {
    UniqueBio bio(BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size())), BIO_free);
    if (!bio) {
      return Result<X509*>::fail(Error::OUT_OF_MEMORY);
    }
    X509* parsed = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (parsed == nullptr) {
      return Result<X509*>::fail(Error::INVALID_ARGUMENT);
    }
    return Result<X509*>::success(std::move(parsed));
  }

  return Result<X509*>::fail(Error::NOT_SUPPORTED);
}

Result<std::vector<X509*>> decodePemChain(const ByteVector& chain_pem) {
  std::vector<X509*> out;
  if (chain_pem.empty()) {
    return Result<std::vector<X509*>>::success(std::move(out));
  }

  UniqueBio bio(BIO_new_mem_buf(chain_pem.data(), static_cast<int>(chain_pem.size())), BIO_free);
  if (!bio) {
    return Result<std::vector<X509*>>::fail(Error::OUT_OF_MEMORY);
  }

  while (true) {
    X509* certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (certificate == nullptr) {
      ERR_clear_error();
      break;
    }
    out.push_back(certificate);
  }

  return Result<std::vector<X509*>>::success(std::move(out));
}

void freeX509Vector(std::vector<X509*>& chain) {
  for (X509* certificate : chain) {
    X509_free(certificate);
  }
  chain.clear();
}

std::string extractNetscapeComment(X509* certificate) {
  int critical = 0;
  int idx = -1;
  ASN1_IA5STRING* comment = static_cast<ASN1_IA5STRING*>(
      X509_get_ext_d2i(certificate, NID_netscape_comment, &critical, &idx));
  if (comment == nullptr) {
    return "";
  }
  const unsigned char* data = ASN1_STRING_get0_data(comment);
  const int len = ASN1_STRING_length(comment);
  const std::string result(reinterpret_cast<const char*>(data), static_cast<size_t>(len));
  ASN1_IA5STRING_free(comment);
  return result;
}

std::optional<std::string> extractJsonStringField(const std::string& json, const std::string& name) {
  const std::string pattern = "\"" + name + "\":";
  const size_t start = json.find(pattern);
  if (start == std::string::npos) {
    return std::nullopt;
  }
  size_t cursor = start + pattern.size();
  while (cursor < json.size() && std::isspace(static_cast<unsigned char>(json[cursor]))) {
    ++cursor;
  }
  if (cursor >= json.size() || json[cursor] != '"') {
    return std::nullopt;
  }
  ++cursor;
  std::ostringstream value;
  bool escaped = false;
  while (cursor < json.size()) {
    const char ch = json[cursor++];
    if (escaped) {
      switch (ch) {
        case '"': value << '"'; break;
        case '\\': value << '\\'; break;
        case '/': value << '/'; break;
        case 'b': value << '\b'; break;
        case 'f': value << '\f'; break;
        case 'n': value << '\n'; break;
        case 'r': value << '\r'; break;
        case 't': value << '\t'; break;
        default: value << ch; break;
      }
      escaped = false;
      continue;
    }
    if (ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == '"') {
      return value.str();
    }
    value << ch;
  }
  return std::nullopt;
}

Result<Curve> parseCurveName(const std::string& name) {
  std::string lowered = name;
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  if (lowered == "secp256k1") return Result<Curve>::success(Curve::SECP256K1);
  if (lowered == "ed25519") return Result<Curve>::success(Curve::ED25519);
  if (lowered == "p256") return Result<Curve>::success(Curve::P256);
  if (lowered == "p384") return Result<Curve>::success(Curve::P384);
  if (lowered == "x25519") return Result<Curve>::success(Curve::X25519);
  return Result<Curve>::fail(Error::INVALID_ARGUMENT);
}

Result<CertificateOptions> parseOptionsSpec(const std::string& spec) {
  CertificateOptions options;
  try {
    std::istringstream input(spec);
    std::string line;
    while (std::getline(input, line)) {
      line = trim(line);
      if (line.empty() || line[0] == '#') {
        continue;
      }
      const auto pos = line.find('=');
      if (pos == std::string::npos) {
        return Result<CertificateOptions>::fail(Error::INVALID_ARGUMENT);
      }
      const std::string key = trim(line.substr(0, pos));
      const std::string value = trim(line.substr(pos + 1));
      if (key == "subject_dn") {
        options.subject_dn = value;
      } else if (key == "serial_hex") {
        options.serial_hex = value;
      } else if (key == "not_before_unix") {
        options.not_before_unix = std::stoll(value);
      } else if (key == "not_after_unix") {
        options.not_after_unix = std::stoll(value);
      } else if (key == "is_ca") {
        options.is_ca = parseBool(value);
      } else if (key == "path_len") {
        options.path_len = std::stoi(value);
      } else if (key == "dns") {
        options.dns_names = splitEscaped(value, ',');
      } else if (key == "ips") {
        options.ip_addresses = splitEscaped(value, ',');
      } else if (key == "emails") {
        options.email_addresses = splitEscaped(value, ',');
      } else if (key == "uris") {
        options.uri_names = splitEscaped(value, ',');
      } else if (key == "key_usage") {
        options.key_usage = splitEscaped(value, ',');
      } else if (key == "extended_key_usage") {
        options.extended_key_usage = splitEscaped(value, ',');
      } else if (key == "friendly_name") {
        options.friendly_name = value;
      } else if (key == "wallet_curve") {
        auto curve = parseCurveName(value);
        if (!curve.ok()) {
          return Result<CertificateOptions>::fail(curve.error);
        }
        options.include_wallet_attestation = true;
        options.wallet_attestation.curve = curve.value;
      } else if (key == "wallet_private_key_hex") {
        auto decoded = hexDecode(value);
        if (!decoded.ok()) {
          return Result<CertificateOptions>::fail(decoded.error);
        }
        options.include_wallet_attestation = true;
        options.wallet_attestation.private_key = std::move(decoded.value);
      } else if (key == "wallet_key_label") {
        options.include_wallet_attestation = true;
        options.wallet_attestation.key_label = value;
      } else if (key == "wallet_comment_prefix") {
        options.include_wallet_attestation = true;
        options.wallet_attestation.comment_prefix = value;
      } else {
        return Result<CertificateOptions>::fail(Error::INVALID_ARGUMENT);
      }
    }
  } catch (...) {
    return Result<CertificateOptions>::fail(Error::INVALID_ARGUMENT);
  }

  if (options.subject_dn.empty() || options.not_before_unix <= 0 || options.not_after_unix <= options.not_before_unix) {
    return Result<CertificateOptions>::fail(Error::INVALID_ARGUMENT);
  }
  if (options.include_wallet_attestation && options.wallet_attestation.private_key.empty()) {
    return Result<CertificateOptions>::fail(Error::INVALID_ARGUMENT);
  }

  return Result<CertificateOptions>::success(std::move(options));
}

Result<std::string> buildParsedCertificateJson(X509* certificate) {
  std::vector<std::string> dns_entries;
  std::vector<std::string> ip_entries;
  std::vector<std::string> email_entries;
  std::vector<std::string> uri_entries;
  bool is_ca = false;

  BASIC_CONSTRAINTS* basic_constraints = static_cast<BASIC_CONSTRAINTS*>(
      X509_get_ext_d2i(certificate, NID_basic_constraints, nullptr, nullptr));
  if (basic_constraints != nullptr) {
    is_ca = basic_constraints->ca > 0;
    BASIC_CONSTRAINTS_free(basic_constraints);
  }

  GENERAL_NAMES* san = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr));
  if (san != nullptr) {
    const int count = sk_GENERAL_NAME_num(san);
    for (int i = 0; i < count; ++i) {
      const GENERAL_NAME* entry = sk_GENERAL_NAME_value(san, i);
      if (entry->type == GEN_DNS) {
        dns_entries.emplace_back(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(entry->d.dNSName)),
            static_cast<size_t>(ASN1_STRING_length(entry->d.dNSName)));
      } else if (entry->type == GEN_EMAIL) {
        email_entries.emplace_back(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(entry->d.rfc822Name)),
            static_cast<size_t>(ASN1_STRING_length(entry->d.rfc822Name)));
      } else if (entry->type == GEN_URI) {
        uri_entries.emplace_back(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(entry->d.uniformResourceIdentifier)),
            static_cast<size_t>(ASN1_STRING_length(entry->d.uniformResourceIdentifier)));
      } else if (entry->type == GEN_IPADD) {
        const unsigned char* ip = ASN1_STRING_get0_data(entry->d.iPAddress);
        const int len = ASN1_STRING_length(entry->d.iPAddress);
        if (len == 4) {
          std::ostringstream oss;
          oss << static_cast<int>(ip[0]) << "."
              << static_cast<int>(ip[1]) << "."
              << static_cast<int>(ip[2]) << "."
              << static_cast<int>(ip[3]);
          ip_entries.push_back(oss.str());
        } else if (len == 16) {
          ip_entries.push_back(hexEncode(ip, static_cast<size_t>(len), true));
        }
      }
    }
    GENERAL_NAMES_free(san);
  }

  const std::string comment = extractNetscapeComment(certificate);
  const ByteVector pem = [&]() {
    auto encoded = encodeCertificate(certificate, Encoding::PEM);
    return encoded.ok() ? encoded.value : ByteVector{};
  }();

  std::ostringstream json;
  json << "{";
  json << "\"subject_dn\":" << jsonString(x509NameToString(X509_get_subject_name(certificate))) << ",";
  json << "\"issuer_dn\":" << jsonString(x509NameToString(X509_get_issuer_name(certificate))) << ",";
  json << "\"serial_hex\":" << jsonString(serialHex(certificate)) << ",";
  json << "\"not_before\":" << jsonString(asn1TimeToString(X509_get0_notBefore(certificate))) << ",";
  json << "\"not_after\":" << jsonString(asn1TimeToString(X509_get0_notAfter(certificate))) << ",";
  json << "\"is_ca\":" << (is_ca ? "true" : "false") << ",";

  auto emitArray = [&](const char* name, const std::vector<std::string>& values) {
    json << "\"" << name << "\":[";
    for (size_t i = 0; i < values.size(); ++i) {
      if (i != 0) {
        json << ",";
      }
      json << jsonString(values[i]);
    }
    json << "]";
  };

  emitArray("dns_names", dns_entries);
  json << ",";
  emitArray("ip_addresses", ip_entries);
  json << ",";
  emitArray("email_addresses", email_entries);
  json << ",";
  emitArray("uri_names", uri_entries);
  json << ",";
  json << "\"wallet_attestation_comment\":" << jsonString(comment) << ",";
  const auto attestation_valid = verifyWalletAttestation(pem, Encoding::PEM);
  json << "\"wallet_attestation_valid\":"
       << (attestation_valid.ok() && attestation_valid.value ? "true" : "false");
  json << "}";
  return Result<std::string>::success(json.str());
}

Result<ByteVector> issueCertificateInternal(
    const CertificateOptions& options,
    Curve issuer_curve,
    const ByteVector& issuer_private_key,
    const std::optional<ByteVector>& issuer_certificate_bytes,
    Encoding issuer_certificate_encoding,
    Curve subject_curve,
    const ByteVector& subject_private_key,
    Encoding output_encoding,
    bool self_signed) {
  const auto* issuer_profile = findCurveProfile(issuer_curve);
  const auto* subject_profile = findCurveProfile(subject_curve);
  if (issuer_profile == nullptr || subject_profile == nullptr ||
      !issuer_profile->certificate_curve || !subject_profile->certificate_curve) {
    return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }

  auto subject_name = parseDistinguishedName(options.subject_dn);
  if (!subject_name.ok()) {
    return Result<ByteVector>::fail(subject_name.error);
  }
  UniqueX509Name subject(subject_name.value, X509_NAME_free);

  UniqueX509 issuer_cert(nullptr, X509_free);
  UniqueX509Name issuer_name(nullptr, X509_NAME_free);

  if (self_signed) {
    issuer_name.reset(X509_NAME_dup(subject.get()));
  } else {
    if (!issuer_certificate_bytes.has_value()) {
      return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }
    auto issuer_parsed = decodeCertificate(*issuer_certificate_bytes, issuer_certificate_encoding);
    if (!issuer_parsed.ok()) {
      return Result<ByteVector>::fail(issuer_parsed.error);
    }
    issuer_cert.reset(issuer_parsed.value);
    issuer_name.reset(X509_NAME_dup(X509_get_subject_name(issuer_cert.get())));
  }
  if (!issuer_name) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }

  auto subject_key_result = makeEcPrivateKey(subject_curve, subject_private_key);
  auto issuer_key_result = self_signed
      ? makeEcPrivateKey(subject_curve, subject_private_key)
      : makeEcPrivateKey(issuer_curve, issuer_private_key);
  if (!subject_key_result.ok() || !issuer_key_result.ok()) {
    return Result<ByteVector>::fail(subject_key_result.ok() ? issuer_key_result.error : subject_key_result.error);
  }
  UniqueEvpPkey subject_key(subject_key_result.value, EVP_PKEY_free);
  UniqueEvpPkey issuer_key(issuer_key_result.value, EVP_PKEY_free);

  UniqueX509 certificate(X509_new(), X509_free);
  if (!certificate) {
    return Result<ByteVector>::fail(Error::OUT_OF_MEMORY);
  }

  auto rc = populateCertificate(certificate.get(), subject.get(), issuer_name.get(), subject_key.get(), options);
  if (!rc.ok()) {
    return Result<ByteVector>::fail(rc.error);
  }

  rc = applyExtensions(certificate.get(), self_signed ? certificate.get() : issuer_cert.get(), options);
  if (!rc.ok()) {
    return Result<ByteVector>::fail(rc.error);
  }

  if (options.include_wallet_attestation) {
    auto comment = buildWalletAttestationComment(certificate.get(), options.wallet_attestation);
    if (!comment.ok()) {
      return Result<ByteVector>::fail(comment.error);
    }
    rc = addCommentExtension(certificate.get(), comment.value);
    if (!rc.ok()) {
      return Result<ByteVector>::fail(rc.error);
    }
  }

  UniqueMd md(EVP_MD_fetch(nullptr, issuer_profile->digest_name, nullptr), EVP_MD_free);
  if (!md) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  if (X509_sign(certificate.get(), issuer_key.get(), md.get()) <= 0) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }

  return encodeCertificate(certificate.get(), output_encoding);
}

} // namespace
#endif

Result<ByteVector> generatePrivateKey(Curve curve) {
#if HD_WALLET_USE_OPENSSL
  const auto* profile = findCurveProfile(curve);
  if (profile == nullptr || !profile->certificate_curve) {
    return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }

  UniqueEvpPkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(profile->group_name), 0),
      OSSL_PARAM_construct_end(),
  };
  if (EVP_PKEY_CTX_set_params(ctx.get(), params) != 1) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }

  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &raw_key) != 1 || raw_key == nullptr) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  UniqueEvpPkey key(raw_key, EVP_PKEY_free);

  BIGNUM* private_bn = nullptr;
  if (EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &private_bn) != 1 || private_bn == nullptr) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  UniqueBn bn(private_bn, BN_clear_free);

  ByteVector out(profile->private_key_size);
  if (BN_bn2binpad(bn.get(), out.data(), static_cast<int>(out.size())) != static_cast<int>(out.size())) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  return Result<ByteVector>::success(std::move(out));
#else
  (void)curve;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<std::string> exportPrivateKeyPem(Curve curve, const ByteVector& private_key) {
#if HD_WALLET_USE_OPENSSL
  auto key_result = makeEcPrivateKey(curve, private_key);
  if (!key_result.ok()) {
    return Result<std::string>::fail(key_result.error);
  }
  UniqueEvpPkey key(key_result.value, EVP_PKEY_free);
  UniqueBio bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio || PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    return Result<std::string>::fail(Error::INTERNAL);
  }
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  if (mem == nullptr || mem->data == nullptr) {
    return Result<std::string>::fail(Error::INTERNAL);
  }
  return Result<std::string>::success(std::string(mem->data, mem->length));
#else
  (void)curve;
  (void)private_key;
  return Result<std::string>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<ByteVector> importPrivateKeyPem(Curve curve, const std::string& pem) {
#if HD_WALLET_USE_OPENSSL
  const auto* profile = findCurveProfile(curve);
  if (profile == nullptr || !profile->certificate_curve) {
    return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
  }
  UniqueBio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  if (!bio) {
    return Result<ByteVector>::fail(Error::OUT_OF_MEMORY);
  }
  UniqueEvpPkey key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (!key) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  BIGNUM* private_bn = nullptr;
  if (EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &private_bn) != 1 || private_bn == nullptr) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  UniqueBn bn(private_bn, BN_clear_free);

  ByteVector out(profile->private_key_size);
  if (BN_bn2binpad(bn.get(), out.data(), static_cast<int>(out.size())) != static_cast<int>(out.size())) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }
  return Result<ByteVector>::success(std::move(out));
#else
  (void)curve;
  (void)pem;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<ByteVector> createSelfSignedCertificate(
    const CertificateOptions& options,
    Curve certificate_curve,
    const ByteVector& certificate_private_key,
    Encoding output_encoding) {
#if HD_WALLET_USE_OPENSSL
  return issueCertificateInternal(
      options,
      certificate_curve,
      certificate_private_key,
      std::nullopt,
      Encoding::PEM,
      certificate_curve,
      certificate_private_key,
      output_encoding,
      true);
#else
  (void)options;
  (void)certificate_curve;
  (void)certificate_private_key;
  (void)output_encoding;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<ByteVector> issueCertificate(
    const CertificateOptions& options,
    Curve issuer_curve,
    const ByteVector& issuer_private_key,
    const ByteVector& issuer_certificate,
    Encoding issuer_certificate_encoding,
    Curve subject_curve,
    const ByteVector& subject_private_key,
    Encoding output_encoding) {
#if HD_WALLET_USE_OPENSSL
  return issueCertificateInternal(
      options,
      issuer_curve,
      issuer_private_key,
      issuer_certificate,
      issuer_certificate_encoding,
      subject_curve,
      subject_private_key,
      output_encoding,
      false);
#else
  (void)options;
  (void)issuer_curve;
  (void)issuer_private_key;
  (void)issuer_certificate;
  (void)issuer_certificate_encoding;
  (void)subject_curve;
  (void)subject_private_key;
  (void)output_encoding;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<ByteVector> convertCertificateEncoding(
    const ByteVector& certificate,
    Encoding input_encoding,
    Encoding output_encoding) {
#if HD_WALLET_USE_OPENSSL
  auto parsed = decodeCertificate(certificate, input_encoding);
  if (!parsed.ok()) {
    return Result<ByteVector>::fail(parsed.error);
  }
  UniqueX509 cert(parsed.value, X509_free);
  return encodeCertificate(cert.get(), output_encoding);
#else
  (void)certificate;
  (void)input_encoding;
  (void)output_encoding;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<std::string> parseCertificateJson(
    const ByteVector& certificate,
    Encoding input_encoding) {
#if HD_WALLET_USE_OPENSSL
  auto parsed = decodeCertificate(certificate, input_encoding);
  if (!parsed.ok()) {
    return Result<std::string>::fail(parsed.error);
  }
  UniqueX509 cert(parsed.value, X509_free);
  return buildParsedCertificateJson(cert.get());
#else
  (void)certificate;
  (void)input_encoding;
  return Result<std::string>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<bool> verifyWalletAttestation(
    const ByteVector& certificate,
    Encoding input_encoding) {
#if HD_WALLET_USE_OPENSSL
  auto parsed = decodeCertificate(certificate, input_encoding);
  if (!parsed.ok()) {
    return Result<bool>::fail(parsed.error);
  }
  UniqueX509 cert(parsed.value, X509_free);
  const std::string comment = extractNetscapeComment(cert.get());
  if (comment.empty()) {
    return Result<bool>::success(false);
  }

  auto curve_name = extractJsonStringField(comment, "curve");
  auto public_key_hex = extractJsonStringField(comment, "public_key_hex");
  auto signature_hex = extractJsonStringField(comment, "signature_hex");
  if (!curve_name.has_value() || !public_key_hex.has_value() || !signature_hex.has_value()) {
    return Result<bool>::success(false);
  }

  auto curve = parseCurveName(*curve_name);
  if (!curve.ok()) {
    return Result<bool>::success(false);
  }
  auto public_key = hexDecode(*public_key_hex);
  auto signature = hexDecode(*signature_hex);
  if (!public_key.ok() || !signature.ok()) {
    return Result<bool>::success(false);
  }

  const ByteVector spki_digest = certificateSpkiDigest(cert.get());
  std::ostringstream payload;
  payload << "version=1\n";
  payload << "serial_hex=" << serialHex(cert.get()) << "\n";
  payload << "issuer_dn=" << x509NameToString(X509_get_issuer_name(cert.get())) << "\n";
  payload << "subject_dn=" << x509NameToString(X509_get_subject_name(cert.get())) << "\n";
  payload << "not_before=" << asn1TimeToString(X509_get0_notBefore(cert.get())) << "\n";
  payload << "not_after=" << asn1TimeToString(X509_get0_notAfter(cert.get())) << "\n";
  payload << "subject_public_key_sha256=" << hexEncode(spki_digest, true) << "\n";

  const std::string payload_text = payload.str();
  const ByteVector payload_bytes(payload_text.begin(), payload_text.end());
  return Result<bool>::success(
      verifyWalletSignature(curve.value, public_key.value, payload_bytes, signature.value));
#else
  (void)certificate;
  (void)input_encoding;
  return Result<bool>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<ByteVector> exportPkcs12(
    const ByteVector& certificate,
    Encoding certificate_encoding,
    Curve private_key_curve,
    const ByteVector& private_key,
    const std::string& password,
    const std::string& friendly_name,
    const ByteVector& chain_pem) {
#if HD_WALLET_USE_OPENSSL
  auto cert_result = decodeCertificate(certificate, certificate_encoding);
  if (!cert_result.ok()) {
    return Result<ByteVector>::fail(cert_result.error);
  }
  UniqueX509 cert(cert_result.value, X509_free);

  auto key_result = makeEcPrivateKey(private_key_curve, private_key);
  if (!key_result.ok()) {
    return Result<ByteVector>::fail(key_result.error);
  }
  UniqueEvpPkey key(key_result.value, EVP_PKEY_free);

  STACK_OF(X509)* ca = nullptr;
  auto chain_result = decodePemChain(chain_pem);
  if (!chain_result.ok()) {
    return Result<ByteVector>::fail(chain_result.error);
  }
  std::vector<X509*> chain = std::move(chain_result.value);
  if (!chain.empty()) {
    ca = sk_X509_new_null();
    if (ca == nullptr) {
      freeX509Vector(chain);
      return Result<ByteVector>::fail(Error::OUT_OF_MEMORY);
    }
    for (X509* extra : chain) {
      sk_X509_push(ca, extra);
    }
    chain.clear();
  }

  UniquePkcs12 pkcs12(
      PKCS12_create(
          password.c_str(),
          friendly_name.empty() ? nullptr : friendly_name.c_str(),
          key.get(),
          cert.get(),
          ca,
          0,
          0,
          0,
          0,
          0),
      PKCS12_free);
  if (ca != nullptr) {
    sk_X509_pop_free(ca, X509_free);
  }
  if (!pkcs12) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }

  int len = i2d_PKCS12(pkcs12.get(), nullptr);
  if (len <= 0) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  ByteVector out(static_cast<size_t>(len));
  unsigned char* cursor = out.data();
  if (i2d_PKCS12(pkcs12.get(), &cursor) != len) {
    return Result<ByteVector>::fail(Error::INTERNAL);
  }
  return Result<ByteVector>::success(std::move(out));
#else
  (void)certificate;
  (void)certificate_encoding;
  (void)private_key_curve;
  (void)private_key;
  (void)password;
  (void)friendly_name;
  (void)chain_pem;
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
#endif
}

Result<std::string> importPkcs12Json(
    const ByteVector& pkcs12_bundle,
    const std::string& password) {
#if HD_WALLET_USE_OPENSSL
  const unsigned char* cursor = pkcs12_bundle.data();
  UniquePkcs12 pkcs12(d2i_PKCS12(nullptr, &cursor, static_cast<long>(pkcs12_bundle.size())), PKCS12_free);
  if (!pkcs12) {
    return Result<std::string>::fail(Error::INVALID_ARGUMENT);
  }

  EVP_PKEY* raw_key = nullptr;
  X509* raw_cert = nullptr;
  STACK_OF(X509)* raw_ca = nullptr;
  if (PKCS12_parse(pkcs12.get(), password.c_str(), &raw_key, &raw_cert, &raw_ca) != 1 ||
      raw_key == nullptr || raw_cert == nullptr) {
    if (raw_key != nullptr) EVP_PKEY_free(raw_key);
    if (raw_cert != nullptr) X509_free(raw_cert);
    if (raw_ca != nullptr) sk_X509_pop_free(raw_ca, X509_free);
    return Result<std::string>::fail(Error::INVALID_ARGUMENT);
  }

  UniqueEvpPkey key(raw_key, EVP_PKEY_free);
  UniqueX509 cert(raw_cert, X509_free);

  UniqueBio cert_bio(BIO_new(BIO_s_mem()), BIO_free);
  UniqueBio key_bio(BIO_new(BIO_s_mem()), BIO_free);
  UniqueBio chain_bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!cert_bio || !key_bio || !chain_bio ||
      PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1 ||
      PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    if (raw_ca != nullptr) sk_X509_pop_free(raw_ca, X509_free);
    return Result<std::string>::fail(Error::INTERNAL);
  }
  if (raw_ca != nullptr) {
    const int count = sk_X509_num(raw_ca);
    for (int i = 0; i < count; ++i) {
      X509* extra = sk_X509_value(raw_ca, i);
      if (PEM_write_bio_X509(chain_bio.get(), extra) != 1) {
        sk_X509_pop_free(raw_ca, X509_free);
        return Result<std::string>::fail(Error::INTERNAL);
      }
    }
    sk_X509_pop_free(raw_ca, X509_free);
  }

  auto bioToString = [](BIO* bio) -> std::string {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (mem == nullptr || mem->data == nullptr) {
      return "";
    }
    return std::string(mem->data, mem->length);
  };

  const std::string cert_pem = bioToString(cert_bio.get());
  const std::string key_pem = bioToString(key_bio.get());
  const std::string chain_pem = bioToString(chain_bio.get());

  std::ostringstream json;
  json << "{";
  json << "\"certificate_pem\":" << jsonString(cert_pem) << ",";
  json << "\"private_key_pem\":" << jsonString(key_pem) << ",";
  json << "\"chain_pem\":" << jsonString(chain_pem);
  json << "}";
  return Result<std::string>::success(json.str());
#else
  (void)pkcs12_bundle;
  (void)password;
  return Result<std::string>::fail(Error::NOT_SUPPORTED);
#endif
}

} // namespace x509
} // namespace hd_wallet

using hd_wallet::ByteVector;
using hd_wallet::Curve;
using hd_wallet::Error;
using hd_wallet::x509::CertificateOptions;
using hd_wallet::x509::Encoding;

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_generate_private_key(
    int32_t curve,
    uint8_t* private_key_out,
    size_t* private_key_out_len) {
  auto result = hd_wallet::x509::generatePrivateKey(static_cast<Curve>(curve));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeBytesToOutput(result.value, private_key_out, private_key_out_len);
#else
  (void)private_key_out;
  (void)private_key_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_export_private_key_pem(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    char* pem_out,
    size_t* pem_out_len) {
  if (private_key == nullptr && private_key_len != 0) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  const ByteVector input = (private_key != nullptr && private_key_len > 0)
      ? ByteVector(private_key, private_key + private_key_len)
      : ByteVector{};
  auto result = hd_wallet::x509::exportPrivateKeyPem(static_cast<Curve>(curve), input);
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeStringToOutput(result.value, pem_out, pem_out_len);
#else
  (void)pem_out;
  (void)pem_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_import_private_key_pem(
    int32_t curve,
    const char* pem,
    uint8_t* private_key_out,
    size_t* private_key_out_len) {
  if (pem == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  auto result = hd_wallet::x509::importPrivateKeyPem(static_cast<Curve>(curve), pem);
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeBytesToOutput(result.value, private_key_out, private_key_out_len);
#else
  (void)private_key_out;
  (void)private_key_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_create_self_signed(
    const char* options_spec,
    int32_t certificate_curve,
    const uint8_t* certificate_private_key,
    size_t certificate_private_key_len,
    int32_t output_encoding,
    uint8_t* certificate_out,
    size_t* certificate_out_len) {
  if (options_spec == nullptr || certificate_private_key == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
#if HD_WALLET_USE_OPENSSL
  auto options = hd_wallet::x509::parseOptionsSpec(options_spec);
  if (!options.ok()) {
    return -static_cast<int32_t>(options.error);
  }
  ByteVector key(certificate_private_key, certificate_private_key + certificate_private_key_len);
  auto result = hd_wallet::x509::createSelfSignedCertificate(
      options.value,
      static_cast<Curve>(certificate_curve),
      key,
      static_cast<Encoding>(output_encoding));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
  return hd_wallet::x509::writeBytesToOutput(result.value, certificate_out, certificate_out_len);
#else
  (void)certificate_private_key_len;
  (void)certificate_out;
  (void)certificate_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_issue_certificate(
    const char* options_spec,
    int32_t issuer_curve,
    const uint8_t* issuer_private_key,
    size_t issuer_private_key_len,
    const uint8_t* issuer_certificate,
    size_t issuer_certificate_len,
    int32_t issuer_certificate_encoding,
    int32_t subject_curve,
    const uint8_t* subject_private_key,
    size_t subject_private_key_len,
    int32_t output_encoding,
    uint8_t* certificate_out,
    size_t* certificate_out_len) {
  if (options_spec == nullptr || issuer_private_key == nullptr ||
      issuer_certificate == nullptr || subject_private_key == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
#if HD_WALLET_USE_OPENSSL
  auto options = hd_wallet::x509::parseOptionsSpec(options_spec);
  if (!options.ok()) {
    return -static_cast<int32_t>(options.error);
  }
  ByteVector issuer_key(issuer_private_key, issuer_private_key + issuer_private_key_len);
  ByteVector issuer_cert(issuer_certificate, issuer_certificate + issuer_certificate_len);
  ByteVector subject_key(subject_private_key, subject_private_key + subject_private_key_len);
  auto result = hd_wallet::x509::issueCertificate(
      options.value,
      static_cast<Curve>(issuer_curve),
      issuer_key,
      issuer_cert,
      static_cast<Encoding>(issuer_certificate_encoding),
      static_cast<Curve>(subject_curve),
      subject_key,
      static_cast<Encoding>(output_encoding));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
  return hd_wallet::x509::writeBytesToOutput(result.value, certificate_out, certificate_out_len);
#else
  (void)issuer_private_key_len;
  (void)issuer_certificate_len;
  (void)subject_private_key_len;
  (void)certificate_out;
  (void)certificate_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_convert_certificate(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding,
    int32_t output_encoding,
    uint8_t* output,
    size_t* output_len) {
  if (certificate == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  ByteVector input(certificate, certificate + certificate_len);
  auto result = hd_wallet::x509::convertCertificateEncoding(
      input, static_cast<Encoding>(input_encoding), static_cast<Encoding>(output_encoding));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeBytesToOutput(result.value, output, output_len);
#else
  (void)output;
  (void)output_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_parse_certificate_json(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding,
    char* json_out,
    size_t* json_out_len) {
  if (certificate == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  ByteVector input(certificate, certificate + certificate_len);
  auto result = hd_wallet::x509::parseCertificateJson(input, static_cast<Encoding>(input_encoding));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeStringToOutput(result.value, json_out, json_out_len);
#else
  (void)json_out;
  (void)json_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_verify_wallet_attestation(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding) {
  if (certificate == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  ByteVector input(certificate, certificate + certificate_len);
  auto result = hd_wallet::x509::verifyWalletAttestation(input, static_cast<Encoding>(input_encoding));
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
  return result.value ? 1 : 0;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_export_pkcs12(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t certificate_encoding,
    int32_t private_key_curve,
    const uint8_t* private_key,
    size_t private_key_len,
    const char* password,
    const char* friendly_name,
    const uint8_t* chain_pem,
    size_t chain_pem_len,
    uint8_t* output,
    size_t* output_len) {
  if (certificate == nullptr || private_key == nullptr || password == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  ByteVector cert_bytes(certificate, certificate + certificate_len);
  ByteVector key_bytes = (private_key_len > 0)
      ? ByteVector(private_key, private_key + private_key_len)
      : ByteVector{};
  ByteVector chain_bytes;
  if (chain_pem != nullptr && chain_pem_len > 0) {
    chain_bytes.assign(chain_pem, chain_pem + chain_pem_len);
  }
  auto result = hd_wallet::x509::exportPkcs12(
      cert_bytes,
      static_cast<Encoding>(certificate_encoding),
      static_cast<Curve>(private_key_curve),
      key_bytes,
      password,
      friendly_name == nullptr ? "" : friendly_name,
      chain_bytes);
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeBytesToOutput(result.value, output, output_len);
#else
  (void)output;
  (void)output_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_x509_import_pkcs12_json(
    const uint8_t* pkcs12_bundle,
    size_t pkcs12_bundle_len,
    const char* password,
    char* json_out,
    size_t* json_out_len) {
  if (pkcs12_bundle == nullptr || password == nullptr) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  ByteVector input(pkcs12_bundle, pkcs12_bundle + pkcs12_bundle_len);
  auto result = hd_wallet::x509::importPkcs12Json(input, password);
  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
#if HD_WALLET_USE_OPENSSL
  return hd_wallet::x509::writeStringToOutput(result.value, json_out, json_out_len);
#else
  (void)json_out;
  (void)json_out_len;
  return -static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}
