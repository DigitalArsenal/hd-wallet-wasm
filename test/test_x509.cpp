/**
 * @file test_x509.cpp
 * @brief X.509 certificate tests
 */

#include "test_framework.h"

#include "hd_wallet/x509.h"

#include <ctime>

using namespace hd_wallet;

namespace {

ByteVector makeWalletKey() {
  ByteVector key(32);
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(i + 1);
  }
  return key;
}

x509::CertificateOptions makeBaseOptions(const std::string& subject_dn) {
  x509::CertificateOptions options;
  options.subject_dn = subject_dn;
  options.serial_hex = "01";
  const auto now = static_cast<int64_t>(std::time(nullptr));
  options.not_before_unix = now - 60;
  options.not_after_unix = now + 86400;
  return options;
}

} // namespace

TEST_CASE(X509, PrivateKeyPemRoundTrip_P256) {
  auto private_key = x509::generatePrivateKey(Curve::P256);
  ASSERT_OK(private_key);
  ASSERT_EQ(32u, private_key.value.size());

  auto pem = x509::exportPrivateKeyPem(Curve::P256, private_key.value);
  ASSERT_OK(pem);
  ASSERT_NE(std::string::npos, pem.value.find("BEGIN PRIVATE KEY"));

  auto imported = x509::importPrivateKeyPem(Curve::P256, pem.value);
  ASSERT_OK(imported);
  ASSERT_EQ(private_key.value.size(), imported.value.size());
  ASSERT_BYTES_EQ(private_key.value.data(), imported.value.data(), private_key.value.size());
}

TEST_CASE(X509, SelfSignedCertificate_WalletAttestation) {
  auto cert_key = x509::generatePrivateKey(Curve::P256);
  ASSERT_OK(cert_key);

  auto options = makeBaseOptions("CN=wallet.example.com,O=Digital Arsenal,C=US");
  options.dns_names = {"wallet.example.com", "www.wallet.example.com"};
  options.key_usage = {"digitalSignature", "keyEncipherment"};
  options.extended_key_usage = {"serverAuth"};
  options.include_wallet_attestation = true;
  options.wallet_attestation.curve = Curve::SECP256K1;
  options.wallet_attestation.private_key = makeWalletKey();
  options.wallet_attestation.key_label = "btc-root";

  auto certificate = x509::createSelfSignedCertificate(
      options,
      Curve::P256,
      cert_key.value,
      x509::Encoding::PEM);
  ASSERT_OK(certificate);
  const std::string certificate_pem(certificate.value.begin(), certificate.value.end());
  ASSERT_NE(std::string::npos, certificate_pem.find("BEGIN CERTIFICATE"));

  auto verified = x509::verifyWalletAttestation(certificate.value, x509::Encoding::PEM);
  ASSERT_OK(verified);
  ASSERT_TRUE(verified.value);

  auto parsed = x509::parseCertificateJson(certificate.value, x509::Encoding::PEM);
  ASSERT_OK(parsed);
  ASSERT_NE(std::string::npos, parsed.value.find("wallet.example.com"));
  ASSERT_NE(std::string::npos, parsed.value.find("\"wallet_attestation_valid\":true"));
  ASSERT_NE(std::string::npos, parsed.value.find("btc-root"));
}

TEST_CASE(X509, IssuerSignedCertificate_P384_AndPkcs12RoundTrip) {
  auto issuer_key = x509::generatePrivateKey(Curve::P384);
  ASSERT_OK(issuer_key);
  auto subject_key = x509::generatePrivateKey(Curve::P384);
  ASSERT_OK(subject_key);

  auto issuer_options = makeBaseOptions("CN=Test Root CA,O=Digital Arsenal,C=US");
  issuer_options.serial_hex = "CA01";
  issuer_options.is_ca = true;
  issuer_options.path_len = 0;
  issuer_options.key_usage = {"keyCertSign", "cRLSign"};

  auto issuer_certificate = x509::createSelfSignedCertificate(
      issuer_options,
      Curve::P384,
      issuer_key.value,
      x509::Encoding::PEM);
  ASSERT_OK(issuer_certificate);

  auto subject_options = makeBaseOptions("CN=leaf.example.com,O=Digital Arsenal,C=US");
  subject_options.serial_hex = "1001";
  subject_options.dns_names = {"leaf.example.com"};
  subject_options.key_usage = {"digitalSignature", "keyEncipherment"};
  subject_options.extended_key_usage = {"serverAuth"};

  auto leaf_certificate = x509::issueCertificate(
      subject_options,
      Curve::P384,
      issuer_key.value,
      issuer_certificate.value,
      x509::Encoding::PEM,
      Curve::P384,
      subject_key.value,
      x509::Encoding::PEM);
  ASSERT_OK(leaf_certificate);

  auto der_leaf = x509::convertCertificateEncoding(
      leaf_certificate.value,
      x509::Encoding::PEM,
      x509::Encoding::DER);
  ASSERT_OK(der_leaf);
  ASSERT_TRUE(!der_leaf.value.empty());

  auto parsed = x509::parseCertificateJson(leaf_certificate.value, x509::Encoding::PEM);
  ASSERT_OK(parsed);
  ASSERT_NE(std::string::npos, parsed.value.find("leaf.example.com"));
  ASSERT_NE(std::string::npos, parsed.value.find("Test Root CA"));

  auto pkcs12 = x509::exportPkcs12(
      leaf_certificate.value,
      x509::Encoding::PEM,
      Curve::P384,
      subject_key.value,
      "secret",
      "leaf-cert");
  ASSERT_OK(pkcs12);
  ASSERT_TRUE(!pkcs12.value.empty());

  auto imported = x509::importPkcs12Json(pkcs12.value, "secret");
  ASSERT_OK(imported);
  ASSERT_NE(std::string::npos, imported.value.find("BEGIN CERTIFICATE"));
  ASSERT_NE(std::string::npos, imported.value.find("BEGIN PRIVATE KEY"));
}
