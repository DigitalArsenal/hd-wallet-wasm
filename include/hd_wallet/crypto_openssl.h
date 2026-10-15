/**
 * @file crypto_openssl.h
 * @brief OpenSSL FIPS Crypto Wrapper Header
 *
 * Declares the C API for OpenSSL 3.x EVP-based crypto operations.
 * Used when HD_WALLET_USE_OPENSSL is defined.
 */

#ifndef HD_WALLET_CRYPTO_OPENSSL_H
#define HD_WALLET_CRYPTO_OPENSSL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize OpenSSL in FIPS mode
 * Loads the FIPS provider and base provider.
 * @return 1 on success, -1 if FIPS not available (uses default), 0 on error
 */
int32_t hd_openssl_init_fips(void);

/**
 * Initialize OpenSSL in default (non-FIPS) mode
 * @return 1 on success, 0 on error
 */
int32_t hd_openssl_init_default(void);

/**
 * Cleanup OpenSSL resources
 * Call when done with all crypto operations
 */
void hd_openssl_cleanup(void);

/**
 * Check if FIPS mode is active
 * @return 1 if FIPS mode, 0 otherwise
 */
int32_t hd_openssl_is_fips(void);

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * SHA-256 hash
 * @param data Input data
 * @param len Input length
 * @param out Output buffer (must be at least 32 bytes)
 * @return 32 on success, negative on error
 */
int32_t hd_ossl_sha256(const uint8_t* data, size_t len, uint8_t* out);

/**
 * SHA-384 hash
 * @param data Input data
 * @param len Input length
 * @param out Output buffer (must be at least 48 bytes)
 * @return 48 on success, negative on error
 */
int32_t hd_ossl_sha384(const uint8_t* data, size_t len, uint8_t* out);

/**
 * SHA-512 hash
 * @param data Input data
 * @param len Input length
 * @param out Output buffer (must be at least 64 bytes)
 * @return 64 on success, negative on error
 */
int32_t hd_ossl_sha512(const uint8_t* data, size_t len, uint8_t* out);

// =============================================================================
// HMAC Functions
// =============================================================================

/**
 * HMAC-SHA256
 * @param key Key bytes
 * @param klen Key length
 * @param data Input data
 * @param dlen Data length
 * @param out Output buffer (must be at least 32 bytes)
 * @return 32 on success, negative on error
 */
int32_t hd_ossl_hmac_sha256(const uint8_t* key, size_t klen,
                            const uint8_t* data, size_t dlen, uint8_t* out);

/**
 * HMAC-SHA512
 * @param key Key bytes
 * @param klen Key length
 * @param data Input data
 * @param dlen Data length
 * @param out Output buffer (must be at least 64 bytes)
 * @return 64 on success, negative on error
 */
int32_t hd_ossl_hmac_sha512(const uint8_t* key, size_t klen,
                            const uint8_t* data, size_t dlen, uint8_t* out);

// =============================================================================
// Key Derivation Functions
// =============================================================================

/**
 * HKDF-SHA256 key derivation
 * @param ikm Input key material
 * @param ikm_len IKM length
 * @param salt Salt (can be NULL if salt_len is 0)
 * @param salt_len Salt length
 * @param info Context info (can be NULL if info_len is 0)
 * @param info_len Info length
 * @param okm Output key material buffer
 * @param okm_len Desired output length
 * @return okm_len on success, negative on error
 */
int32_t hd_ossl_hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len);

/**
 * HKDF-SHA384 key derivation
 */
int32_t hd_ossl_hkdf_sha384(const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len);

/**
 * PBKDF2-SHA512 key derivation
 * @param pwd Password bytes
 * @param pwd_len Password length
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param iterations Number of iterations (typically 2048 for BIP-39)
 * @param out Output buffer
 * @param out_len Desired output length
 * @return out_len on success, negative on error
 */
int32_t hd_ossl_pbkdf2_sha512(const uint8_t* pwd, size_t pwd_len,
                              const uint8_t* salt, size_t salt_len,
                              uint32_t iterations,
                              uint8_t* out, size_t out_len);

// =============================================================================
// AES-GCM Encryption
// =============================================================================

/**
 * AES-256-GCM authenticated encryption
 * @param key 32-byte key
 * @param key_len Key length (must be 32)
 * @param pt Plaintext
 * @param pt_len Plaintext length
 * @param iv 12-byte IV (recommended)
 * @param iv_len IV length
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param ct Ciphertext output buffer (must be at least pt_len bytes)
 * @param tag 16-byte authentication tag output
 * @return Ciphertext length on success, negative on error
 */
int32_t hd_ossl_aes_gcm_encrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* pt, size_t pt_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* aad, size_t aad_len,
                                uint8_t* ct, uint8_t* tag);

/**
 * AES-256-GCM authenticated decryption
 * @param key 32-byte key
 * @param key_len Key length (must be 32)
 * @param ct Ciphertext
 * @param ct_len Ciphertext length
 * @param iv 12-byte IV
 * @param iv_len IV length
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param tag 16-byte authentication tag
 * @param pt Plaintext output buffer (must be at least ct_len bytes)
 * @return Plaintext length on success, -2 on auth failure, other negative on error
 */
int32_t hd_ossl_aes_gcm_decrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* ct, size_t ct_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* tag,
                                uint8_t* pt);

// =============================================================================
// AES-CTR Encryption
// =============================================================================

/**
 * AES-256-CTR encryption
 * @param key 32-byte key
 * @param key_len Key length (must be 16, 24, or 32)
 * @param pt Plaintext
 * @param pt_len Plaintext length
 * @param iv 16-byte IV/nonce
 * @param iv_len IV length (must be 16)
 * @param ct Ciphertext output buffer (must be at least pt_len bytes)
 * @return Ciphertext length on success, negative on error
 */
int32_t hd_ossl_aes_ctr_encrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* pt, size_t pt_len,
                                const uint8_t* iv, size_t iv_len,
                                uint8_t* ct);

/**
 * AES-256-CTR decryption (same operation as encrypt for CTR mode)
 * @param key 32-byte key
 * @param key_len Key length (must be 16, 24, or 32)
 * @param ct Ciphertext
 * @param ct_len Ciphertext length
 * @param iv 16-byte IV/nonce
 * @param iv_len IV length (must be 16)
 * @param pt Plaintext output buffer (must be at least ct_len bytes)
 * @return Plaintext length on success, negative on error
 */
int32_t hd_ossl_aes_ctr_decrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* ct, size_t ct_len,
                                const uint8_t* iv, size_t iv_len,
                                uint8_t* pt);

// =============================================================================
// ECDSA (NIST curves)
// =============================================================================

/* OpenSSL NID values for reference:
 * NID_X9_62_prime256v1 = 415 (P-256)
 * NID_secp384r1 = 715 (P-384)
 */

/**
 * ECDSA sign using NIST curve
 * @param curve_nid OpenSSL NID for the curve
 * @param privkey Private key bytes
 * @param pk_len Private key length
 * @param hash Message hash to sign
 * @param hash_len Hash length
 * @param sig Signature output buffer (DER format)
 * @param sig_len Input: buffer size, Output: actual signature length
 * @return 0 on success, negative on error
 */
int32_t hd_ossl_ecdsa_sign(int curve_nid,
                           const uint8_t* privkey, size_t pk_len,
                           const uint8_t* hash, size_t hash_len,
                           uint8_t* sig, size_t* sig_len);

/**
 * ECDSA verify using NIST curve
 * @param curve_nid OpenSSL NID for the curve
 * @param pubkey Public key (uncompressed format: 0x04 || x || y)
 * @param pub_len Public key length
 * @param hash Message hash
 * @param hash_len Hash length
 * @param sig Signature (DER format)
 * @param sig_len Signature length
 * @return 0 if valid, -2 if invalid signature, other negative on error
 */
int32_t hd_ossl_ecdsa_verify(int curve_nid,
                             const uint8_t* pubkey, size_t pub_len,
                             const uint8_t* hash, size_t hash_len,
                             const uint8_t* sig, size_t sig_len);

/**
 * Check a NIST public key encoding (SEC1 02/03 compressed or 04 uncompressed)
 * decodes to a point of the curve other than infinity and re-encodes to the
 * same bytes (no coordinate >= p, no hybrid encoding).
 * @param curve_nid NID_X9_62_prime256v1 or NID_secp384r1
 * @return 0 when valid, -1 otherwise
 */
int32_t hd_ossl_ec_pubkey_check(int curve_nid,
                                const uint8_t* pubkey, size_t pub_len);

/**
 * Derive public key from private key for NIST curves
 * @param curve_nid OpenSSL NID for the curve
 * @param privkey Private key bytes
 * @param pk_len Private key length
 * @param pubkey Output buffer for public key (uncompressed format)
 * @param pub_len Input: buffer size, Output: actual public key length
 * @return 0 on success, negative on error
 */
int32_t hd_ossl_ec_pubkey_from_privkey(int curve_nid,
                                       const uint8_t* privkey, size_t pk_len,
                                       uint8_t* pubkey, size_t* pub_len);

// =============================================================================
// ECDH (NIST curves)
// =============================================================================

/**
 * Generate ECDH key pair
 * @param curve_nid OpenSSL NID for the curve
 * @param privkey Output buffer for private key (32 bytes for P-256, 48 for P-384)
 * @param pubkey Output buffer for public key (65 bytes for P-256, 97 for P-384)
 * @return 0 on success, negative on error
 */
int32_t hd_ossl_ecdh_keygen(int curve_nid,
                            uint8_t* privkey, uint8_t* pubkey);

/**
 * Compute ECDH shared secret
 * @param curve_nid OpenSSL NID for the curve
 * @param privkey Private key bytes
 * @param pk_len Private key length
 * @param peer_pubkey Peer's public key (uncompressed format)
 * @param peer_len Peer public key length
 * @param shared_secret Output buffer for shared secret
 * @param ss_len Input: buffer size, Output: actual shared secret length
 * @return 0 on success, negative on error
 */
int32_t hd_ossl_ecdh_compute(int curve_nid,
                             const uint8_t* privkey, size_t pk_len,
                             const uint8_t* peer_pubkey, size_t peer_len,
                             uint8_t* shared_secret, size_t* ss_len);

#ifdef __cplusplus
}
#endif

#endif // HD_WALLET_CRYPTO_OPENSSL_H
