/**
 * @file x509.h
 * @brief X.509 Certificate Utilities
 *
 * OpenSSL-backed certificate generation, signing, import/export, and
 * wallet-attestation helpers.
 */

#ifndef HD_WALLET_X509_H
#define HD_WALLET_X509_H

#include "config.h"
#include "types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hd_wallet {
namespace x509 {

enum class Encoding : int32_t {
  PEM = 0,
  DER = 1,
  PKCS12 = 2
};

struct WalletAttestationRequest {
  Curve curve = Curve::SECP256K1;
  ByteVector private_key;
  std::string key_label;
  std::string comment_prefix = "HDWALLET-X509";
};

struct CertificateOptions {
  std::string subject_dn;
  std::string serial_hex = "01";
  int64_t not_before_unix = 0;
  int64_t not_after_unix = 0;
  bool is_ca = false;
  int32_t path_len = -1;
  std::vector<std::string> dns_names;
  std::vector<std::string> ip_addresses;
  std::vector<std::string> email_addresses;
  std::vector<std::string> uri_names;
  std::vector<std::string> key_usage;
  std::vector<std::string> extended_key_usage;
  std::string friendly_name;
  bool include_wallet_attestation = false;
  WalletAttestationRequest wallet_attestation;
};

Result<ByteVector> generatePrivateKey(Curve curve);
Result<std::string> exportPrivateKeyPem(Curve curve, const ByteVector& private_key);
Result<ByteVector> importPrivateKeyPem(Curve curve, const std::string& pem);

Result<ByteVector> createSelfSignedCertificate(
    const CertificateOptions& options,
    Curve certificate_curve,
    const ByteVector& certificate_private_key,
    Encoding output_encoding = Encoding::PEM
);

Result<ByteVector> issueCertificate(
    const CertificateOptions& options,
    Curve issuer_curve,
    const ByteVector& issuer_private_key,
    const ByteVector& issuer_certificate,
    Encoding issuer_certificate_encoding,
    Curve subject_curve,
    const ByteVector& subject_private_key,
    Encoding output_encoding = Encoding::PEM
);

Result<ByteVector> convertCertificateEncoding(
    const ByteVector& certificate,
    Encoding input_encoding,
    Encoding output_encoding
);

Result<std::string> parseCertificateJson(
    const ByteVector& certificate,
    Encoding input_encoding
);

Result<bool> verifyWalletAttestation(
    const ByteVector& certificate,
    Encoding input_encoding
);

Result<ByteVector> exportPkcs12(
    const ByteVector& certificate,
    Encoding certificate_encoding,
    Curve private_key_curve,
    const ByteVector& private_key,
    const std::string& password,
    const std::string& friendly_name = "",
    const ByteVector& chain_pem = {}
);

Result<std::string> importPkcs12Json(
    const ByteVector& pkcs12_bundle,
    const std::string& password
);

} // namespace x509
} // namespace hd_wallet

// =============================================================================
// C API
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_generate_private_key(
    int32_t curve,
    uint8_t* private_key_out,
    size_t* private_key_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_export_private_key_pem(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    char* pem_out,
    size_t* pem_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_import_private_key_pem(
    int32_t curve,
    const char* pem,
    uint8_t* private_key_out,
    size_t* private_key_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_create_self_signed(
    const char* options_spec,
    int32_t certificate_curve,
    const uint8_t* certificate_private_key,
    size_t certificate_private_key_len,
    int32_t output_encoding,
    uint8_t* certificate_out,
    size_t* certificate_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
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
    size_t* certificate_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_convert_certificate(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding,
    int32_t output_encoding,
    uint8_t* output,
    size_t* output_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_parse_certificate_json(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding,
    char* json_out,
    size_t* json_out_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_verify_wallet_attestation(
    const uint8_t* certificate,
    size_t certificate_len,
    int32_t input_encoding
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
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
    size_t* output_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x509_import_pkcs12_json(
    const uint8_t* pkcs12_bundle,
    size_t pkcs12_bundle_len,
    const char* password,
    char* json_out,
    size_t* json_out_len
);

#endif // HD_WALLET_X509_H
