/**
 * @file crypto_openssl.c
 * @brief OpenSSL FIPS Crypto Wrapper for HD Wallet WASM
 *
 * Provides a C API bridge to OpenSSL 3.x EVP APIs for FIPS-approved algorithms.
 * This file is compiled only when HD_WALLET_USE_OPENSSL is defined.
 *
 * FIPS-approved algorithms routed through OpenSSL:
 * - SHA-256, SHA-384, SHA-512
 * - HMAC-SHA256, HMAC-SHA512
 * - HKDF-SHA256, HKDF-SHA384
 * - PBKDF2-SHA512
 * - AES-256-GCM, AES-256-CTR
 * - ECDSA P-256, P-384
 * - ECDH P-256, P-384
 *
 * Non-FIPS algorithms still use Crypto++:
 * - secp256k1 (Bitcoin/Ethereum)
 * - Ed25519 (Solana, Cosmos)
 * - X25519 (key exchange)
 * - Keccak-256 (Ethereum)
 * - BLAKE2b, BLAKE2s
 * - RIPEMD-160
 * - scrypt
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define HD_OSSL_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define HD_OSSL_EXPORT
#endif

// Thread safety for platforms that support it
#if defined(__EMSCRIPTEN__) && defined(__EMSCRIPTEN_PTHREADS__)
#include <pthread.h>
static pthread_mutex_t openssl_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK_OPENSSL() pthread_mutex_lock(&openssl_mutex)
#define UNLOCK_OPENSSL() pthread_mutex_unlock(&openssl_mutex)
#else
// Single-threaded WASM - no locking needed
#define LOCK_OPENSSL() ((void)0)
#define UNLOCK_OPENSSL() ((void)0)
#endif

// =============================================================================
// Global Context (protected by mutex in threaded builds)
// =============================================================================

static OSSL_LIB_CTX *fips_libctx = NULL;
static OSSL_PROVIDER *fips_prov = NULL;
static OSSL_PROVIDER *base_prov = NULL;
static int openssl_initialized = 0;
static int fips_mode_active = 0;
static char fips_error_message[1024] = {0};

// =============================================================================
// Initialization
// =============================================================================

/**
 * Get the last FIPS error message
 * @return Error message string (empty if no error)
 */
HD_OSSL_EXPORT
const char* hd_openssl_get_error(void) {
    return fips_error_message;
}

/**
 * Initialize OpenSSL FIPS mode
 * @return 1 on success, -1 if FIPS not available (fallback mode), 0 on error
 *
 * WARNING: FIPS mode requires:
 * 1. OpenSSL 3.x built with FIPS provider
 * 2. FIPS module file (fips.so/fips.dll) accessible via OPENSSL_MODULES path
 * 3. FIPS self-tests to pass at runtime
 *
 * In WASM environments, FIPS mode will likely fail due to:
 * - No filesystem access for FIPS module loading
 * - No persistent storage for FIPS installation status
 *
 * Use hd_openssl_get_error() to get detailed failure information.
 */
HD_OSSL_EXPORT
int32_t hd_openssl_init_fips(void) {
    LOCK_OPENSSL();

    if (openssl_initialized) {
        int result = fips_mode_active ? 1 : -1;
        UNLOCK_OPENSSL();
        return result;
    }

    fips_error_message[0] = '\0';

    // Create a library context for FIPS
    fips_libctx = OSSL_LIB_CTX_new();
    if (fips_libctx == NULL) {
        unsigned long err = ERR_get_error();
        snprintf(fips_error_message, sizeof(fips_error_message),
                 "Failed to create OpenSSL library context: %s",
                 ERR_error_string(err, NULL));
        UNLOCK_OPENSSL();
        return 0;
    }

    // Load the FIPS provider
    fips_prov = OSSL_PROVIDER_load(fips_libctx, "fips");
    if (fips_prov == NULL) {
        // FIPS provider not available, record error and fall back to default
        unsigned long err = ERR_get_error();
        snprintf(fips_error_message, sizeof(fips_error_message),
                 "FIPS provider not available (check OPENSSL_MODULES path): %s. "
                 "Falling back to non-FIPS mode.",
                 ERR_error_string(err, NULL));

        OSSL_LIB_CTX_free(fips_libctx);
        fips_libctx = NULL;
        openssl_initialized = 1;
        fips_mode_active = 0;
        UNLOCK_OPENSSL();
        return -1; // Indicate fallback mode
    }

    // Load base provider for non-crypto operations
    base_prov = OSSL_PROVIDER_load(fips_libctx, "base");
    if (base_prov == NULL) {
        // Base provider needed, but continue anyway
        snprintf(fips_error_message, sizeof(fips_error_message),
                 "Warning: base provider failed to load, some operations may fail");
    }

    openssl_initialized = 1;
    fips_mode_active = 1;
    UNLOCK_OPENSSL();
    return 1;
}

/**
 * Initialize in non-FIPS mode (for development/testing)
 * @return 1 on success, 0 on error
 */
HD_OSSL_EXPORT
int32_t hd_openssl_init_default(void) {
    LOCK_OPENSSL();
    if (openssl_initialized) {
        UNLOCK_OPENSSL();
        return 1;
    }

    // OpenSSL default provider is loaded automatically
    openssl_initialized = 1;
    fips_mode_active = 0;
    UNLOCK_OPENSSL();
    return 1;
}

/**
 * Cleanup OpenSSL resources
 */
HD_OSSL_EXPORT
void hd_openssl_cleanup(void) {
    LOCK_OPENSSL();
    if (fips_prov) {
        OSSL_PROVIDER_unload(fips_prov);
        fips_prov = NULL;
    }
    if (base_prov) {
        OSSL_PROVIDER_unload(base_prov);
        base_prov = NULL;
    }
    if (fips_libctx) {
        OSSL_LIB_CTX_free(fips_libctx);
        fips_libctx = NULL;
    }
    openssl_initialized = 0;
    fips_mode_active = 0;
    fips_error_message[0] = '\0';
    UNLOCK_OPENSSL();
}

/**
 * Check if FIPS mode is active
 * @return 1 if FIPS mode, 0 otherwise
 */
HD_OSSL_EXPORT
int32_t hd_openssl_is_fips(void) {
    return fips_mode_active ? 1 : 0;
}

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * SHA-256 hash
 * @param data Input data (must not be NULL)
 * @param len Input length
 * @param out Output buffer (32 bytes, must not be NULL)
 * @return 32 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_sha256(const uint8_t* data, size_t len, uint8_t* out) {
    if (data == NULL || out == NULL) return -3;  // Invalid argument

    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int hash_len = 32;
    int ret = -1;

    md = EVP_MD_fetch(fips_libctx, "SHA256", NULL);
    if (md == NULL) goto cleanup;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) goto cleanup;
    if (EVP_DigestUpdate(ctx, data, len) != 1) goto cleanup;
    if (EVP_DigestFinal_ex(ctx, out, &hash_len) != 1) goto cleanup;

    ret = 32;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

/**
 * SHA-384 hash
 * @param data Input data
 * @param len Input length
 * @param out Output buffer (48 bytes)
 * @return 48 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_sha384(const uint8_t* data, size_t len, uint8_t* out) {
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int hash_len = 48;
    int ret = -1;

    md = EVP_MD_fetch(fips_libctx, "SHA384", NULL);
    if (md == NULL) goto cleanup;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) goto cleanup;
    if (EVP_DigestUpdate(ctx, data, len) != 1) goto cleanup;
    if (EVP_DigestFinal_ex(ctx, out, &hash_len) != 1) goto cleanup;

    ret = 48;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

/**
 * SHA-512 hash
 * @param data Input data
 * @param len Input length
 * @param out Output buffer (64 bytes)
 * @return 64 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_sha512(const uint8_t* data, size_t len, uint8_t* out) {
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int hash_len = 64;
    int ret = -1;

    md = EVP_MD_fetch(fips_libctx, "SHA512", NULL);
    if (md == NULL) goto cleanup;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) goto cleanup;
    if (EVP_DigestUpdate(ctx, data, len) != 1) goto cleanup;
    if (EVP_DigestFinal_ex(ctx, out, &hash_len) != 1) goto cleanup;

    ret = 64;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

// =============================================================================
// HMAC Functions
// =============================================================================

/**
 * HMAC-SHA256
 * @param key Key bytes
 * @param klen Key length
 * @param data Input data
 * @param dlen Data length
 * @param out Output buffer (32 bytes)
 * @return 32 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_hmac_sha256(const uint8_t* key, size_t klen,
                            const uint8_t* data, size_t dlen, uint8_t* out) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    size_t out_len = 32;
    int ret = -1;

    mac = EVP_MAC_fetch(fips_libctx, "HMAC", NULL);
    if (mac == NULL) goto cleanup;

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, klen, params) != 1) goto cleanup;
    if (EVP_MAC_update(ctx, data, dlen) != 1) goto cleanup;
    if (EVP_MAC_final(ctx, out, &out_len, 32) != 1) goto cleanup;

    ret = 32;

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

/**
 * HMAC-SHA512
 * @param key Key bytes
 * @param klen Key length
 * @param data Input data
 * @param dlen Data length
 * @param out Output buffer (64 bytes)
 * @return 64 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_hmac_sha512(const uint8_t* key, size_t klen,
                            const uint8_t* data, size_t dlen, uint8_t* out) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    size_t out_len = 64;
    int ret = -1;

    mac = EVP_MAC_fetch(fips_libctx, "HMAC", NULL);
    if (mac == NULL) goto cleanup;

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, klen, params) != 1) goto cleanup;
    if (EVP_MAC_update(ctx, data, dlen) != 1) goto cleanup;
    if (EVP_MAC_final(ctx, out, &out_len, 64) != 1) goto cleanup;

    ret = 64;

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

// =============================================================================
// Key Derivation Functions
// =============================================================================

/**
 * HKDF-SHA256 key derivation
 * @param ikm Input key material
 * @param ikm_len IKM length
 * @param salt Salt (can be NULL)
 * @param salt_len Salt length
 * @param info Context info
 * @param info_len Info length
 * @param okm Output key material buffer
 * @param okm_len Desired output length
 * @return okm_len on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int ret = -1;

    kdf = EVP_KDF_fetch(fips_libctx, "HKDF", NULL);
    if (kdf == NULL) goto cleanup;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, okm, okm_len, params) != 1) goto cleanup;

    ret = (int32_t)okm_len;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/**
 * HKDF-SHA384 key derivation
 */
HD_OSSL_EXPORT
int32_t hd_ossl_hkdf_sha384(const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int ret = -1;

    kdf = EVP_KDF_fetch(fips_libctx, "HKDF", NULL);
    if (kdf == NULL) goto cleanup;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA384", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, okm, okm_len, params) != 1) goto cleanup;

    ret = (int32_t)okm_len;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/**
 * PBKDF2-SHA512 key derivation
 * @param pwd Password
 * @param pwd_len Password length
 * @param salt Salt
 * @param salt_len Salt length
 * @param iterations Iteration count
 * @param out Output buffer
 * @param out_len Desired output length
 * @return out_len on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_pbkdf2_sha512(const uint8_t* pwd, size_t pwd_len,
                              const uint8_t* salt, size_t salt_len,
                              uint32_t iterations,
                              uint8_t* out, size_t out_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int ret = -1;
    unsigned int iter = iterations;

    kdf = EVP_KDF_fetch(fips_libctx, "PBKDF2", NULL);
    if (kdf == NULL) goto cleanup;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pwd, pwd_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) != 1) goto cleanup;

    ret = (int32_t)out_len;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

// =============================================================================
// AES-GCM Encryption
// =============================================================================

/**
 * AES-256-GCM authenticated encryption
 * @param key 32-byte key
 * @param key_len Key length (must be 32)
 * @param pt Plaintext
 * @param pt_len Plaintext length
 * @param iv 12-byte IV
 * @param iv_len IV length (should be 12)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param ct Ciphertext output buffer (same size as plaintext)
 * @param tag 16-byte authentication tag output
 * @return Ciphertext length on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_aes_gcm_encrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* pt, size_t pt_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* aad, size_t aad_len,
                                uint8_t* ct, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int ct_len = 0;
    int ret = -1;

    if (key_len != 32) return -1;

    cipher = EVP_CIPHER_fetch(fips_libctx, "AES-256-GCM", NULL);
    if (cipher == NULL) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) goto cleanup;

    // Set IV length if not 12
    if (iv_len != 12) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto cleanup;
    }

    // Process AAD
    if (aad_len > 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto cleanup;
    ct_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto cleanup;
    ct_len += len;

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto cleanup;

    ret = ct_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/**
 * AES-256-GCM authenticated decryption
 * @param key 32-byte key
 * @param key_len Key length (must be 32)
 * @param ct Ciphertext
 * @param ct_len Ciphertext length
 * @param iv 12-byte IV
 * @param iv_len IV length (should be 12)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param tag 16-byte authentication tag
 * @param pt Plaintext output buffer
 * @return Plaintext length on success, negative on error (including auth failure)
 */
HD_OSSL_EXPORT
int32_t hd_ossl_aes_gcm_decrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* ct, size_t ct_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* tag,
                                uint8_t* pt) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int pt_len = 0;
    int ret = -1;

    if (key_len != 32) return -1;

    cipher = EVP_CIPHER_fetch(fips_libctx, "AES-256-GCM", NULL);
    if (cipher == NULL) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) goto cleanup;

    // Set IV length if not 12
    if (iv_len != 12) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto cleanup;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto cleanup;

    // Process AAD
    if (aad_len > 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto cleanup;
    pt_len = len;

    // Verify tag
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) {
        // Authentication failed
        ret = -2;
        goto cleanup;
    }
    pt_len += len;

    ret = pt_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

// =============================================================================
// AES-CTR
// =============================================================================

static const char* aes_ctr_cipher_name(size_t key_len) {
    switch (key_len) {
        case 16: return "AES-128-CTR";
        case 24: return "AES-192-CTR";
        case 32: return "AES-256-CTR";
        default: return NULL;
    }
}

HD_OSSL_EXPORT
int32_t hd_ossl_aes_ctr_encrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* pt, size_t pt_len,
                                const uint8_t* iv, size_t iv_len,
                                uint8_t* ct) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int ct_len = 0;
    int ret = -1;

    const char* cipher_name = aes_ctr_cipher_name(key_len);
    if (!cipher_name || iv_len != 16) return -1;

    cipher = EVP_CIPHER_fetch(fips_libctx, cipher_name, NULL);
    if (cipher == NULL) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) goto cleanup;

    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) goto cleanup;

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto cleanup;
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto cleanup;
    ct_len += len;

    ret = ct_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

HD_OSSL_EXPORT
int32_t hd_ossl_aes_ctr_decrypt(const uint8_t* key, size_t key_len,
                                const uint8_t* ct, size_t ct_len,
                                const uint8_t* iv, size_t iv_len,
                                uint8_t* pt) {
    /* CTR mode decryption is identical to encryption */
    return hd_ossl_aes_ctr_encrypt(key, key_len, ct, ct_len, iv, iv_len, pt);
}

// =============================================================================
// ECDSA (P-256, P-384)
// =============================================================================

/**
 * ECDSA sign with NIST curve
 * @param curve_nid OpenSSL NID (NID_X9_62_prime256v1 for P-256, NID_secp384r1 for P-384)
 * @param privkey Private key bytes
 * @param pk_len Private key length (32 for P-256, 48 for P-384)
 * @param hash Message hash
 * @param hash_len Hash length
 * @param sig Signature output buffer (max 72 for P-256, 104 for P-384)
 * @param sig_len Output: actual signature length
 * @return 0 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ecdsa_sign(int curve_nid,
                           const uint8_t* privkey, size_t pk_len,
                           const uint8_t* hash, size_t hash_len,
                           uint8_t* sig, size_t* sig_len) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *priv_bn = NULL;
    const char *curve_name = NULL;
    int ret = -1;

    // Determine curve name
    if (curve_nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
    } else if (curve_nid == NID_secp384r1) {
        curve_name = "P-384";
    } else {
        return -1;
    }

    // Convert raw private key bytes to BIGNUM
    priv_bn = BN_bin2bn(privkey, (int)pk_len, NULL);
    if (priv_bn == NULL) goto cleanup;

    // Build private key
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto cleanup;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn)) goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) goto cleanup;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    // Sign
    pctx = EVP_PKEY_CTX_new_from_pkey(fips_libctx, pkey, NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_sign_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_sign(pctx, sig, sig_len, hash, hash_len) != 1) goto cleanup;

    ret = 0;

cleanup:
    BN_clear_free(priv_bn);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * ECDSA verify with NIST curve
 * @param curve_nid OpenSSL NID
 * @param pubkey Public key (uncompressed, 65 bytes for P-256, 97 for P-384)
 * @param pub_len Public key length
 * @param hash Message hash
 * @param hash_len Hash length
 * @param sig Signature
 * @param sig_len Signature length
 * @return 0 on success (valid), negative on error or invalid signature
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ecdsa_verify(int curve_nid,
                             const uint8_t* pubkey, size_t pub_len,
                             const uint8_t* hash, size_t hash_len,
                             const uint8_t* sig, size_t sig_len) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *curve_name = NULL;
    int ret = -1;

    // Determine curve name
    if (curve_nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
    } else if (curve_nid == NID_secp384r1) {
        curve_name = "P-384";
    } else {
        return -1;
    }

    // Build public key
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto cleanup;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pub_len)) goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) goto cleanup;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    // Verify
    pctx = EVP_PKEY_CTX_new_from_pkey(fips_libctx, pkey, NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_verify_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_verify(pctx, sig, sig_len, hash, hash_len) != 1) {
        ret = -2; // Invalid signature
        goto cleanup;
    }

    ret = 0;

cleanup:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * Check a NIST public key encoding: SEC1 compressed (02/03 || x) or
 * uncompressed (04 || x || y) at the curve's size, decoding to a point of the
 * curve other than infinity. The point must re-encode to the same bytes, so a
 * coordinate >= p (which decoding would reduce) is refused, as are hybrid
 * (06/07) encodings.
 * @param curve_nid NID_X9_62_prime256v1 or NID_secp384r1
 * @return 0 when valid, -1 otherwise
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ec_pubkey_check(int curve_nid,
                                const uint8_t* pubkey, size_t pub_len) {
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BN_CTX *bn_ctx = NULL;
    unsigned char reencoded[97];
    point_conversion_form_t form;
    size_t field_size;
    int32_t ret = -1;

    if (pubkey == NULL) return -1;
    if (curve_nid == NID_X9_62_prime256v1) {
        field_size = 32;
    } else if (curve_nid == NID_secp384r1) {
        field_size = 48;
    } else {
        return -1;
    }
    if (pub_len == field_size + 1 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)) {
        form = POINT_CONVERSION_COMPRESSED;
    } else if (pub_len == 2 * field_size + 1 && pubkey[0] == 0x04) {
        form = POINT_CONVERSION_UNCOMPRESSED;
    } else {
        return -1;
    }

    group = EC_GROUP_new_by_curve_name_ex(fips_libctx, NULL, curve_nid);
    bn_ctx = BN_CTX_new_ex(fips_libctx);
    if (group == NULL || bn_ctx == NULL) goto cleanup;
    point = EC_POINT_new(group);
    if (point == NULL) goto cleanup;
    if (EC_POINT_oct2point(group, point, pubkey, pub_len, bn_ctx) != 1) goto cleanup;
    if (EC_POINT_is_at_infinity(group, point)) goto cleanup;
    if (EC_POINT_is_on_curve(group, point, bn_ctx) != 1) goto cleanup;
    if (EC_POINT_point2oct(group, point, form, reencoded, sizeof(reencoded), bn_ctx) != pub_len) {
        goto cleanup;
    }
    if (CRYPTO_memcmp(reencoded, pubkey, pub_len) != 0) goto cleanup;
    ret = 0;

cleanup:
    EC_POINT_free(point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/**
 * Derive public key from private key for NIST curves
 * @param curve_nid OpenSSL NID
 * @param privkey Private key bytes
 * @param pk_len Private key length
 * @param pubkey Output buffer for public key (uncompressed format)
 * @param pub_len Output: actual public key length
 * @return 0 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ec_pubkey_from_privkey(int curve_nid,
                                       const uint8_t* privkey, size_t pk_len,
                                       uint8_t* pubkey, size_t* pub_len) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *priv_bn = NULL;
    const char *curve_name = NULL;
    int ret = -1;

    // Determine curve name
    if (curve_nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
    } else if (curve_nid == NID_secp384r1) {
        curve_name = "P-384";
    } else {
        return -1;
    }

    priv_bn = BN_bin2bn(privkey, (int)pk_len, NULL);
    if (priv_bn == NULL) goto cleanup;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto cleanup;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn)) goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) goto cleanup;

    // Extract public key
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey, *pub_len, pub_len) != 1) goto cleanup;

    ret = 0;

cleanup:
    BN_clear_free(priv_bn);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

// =============================================================================
// ECDH (P-256, P-384)
// =============================================================================

/**
 * Generate ECDH key pair
 * @param curve_nid OpenSSL NID
 * @param privkey Output buffer for private key
 * @param pubkey Output buffer for public key (uncompressed)
 * @return 0 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ecdh_keygen(int curve_nid,
                            uint8_t* privkey, uint8_t* pubkey) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *priv_bn = NULL;
    size_t pub_len;
    size_t priv_size;
    const char *curve_name = NULL;
    int ret = -1;

    if (curve_nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
        pub_len = 65;
        priv_size = 32;
    } else if (curve_nid == NID_secp384r1) {
        curve_name = "P-384";
        pub_len = 97;
        priv_size = 48;
    } else {
        return -1;
    }

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;

    if (EVP_PKEY_keygen_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) != 1) goto cleanup;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) goto cleanup;

    // Extract private key
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) != 1) goto cleanup;
    BN_bn2binpad(priv_bn, privkey, (int)priv_size);

    // Extract public key
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey, pub_len, &pub_len) != 1) goto cleanup;

    ret = 0;

cleanup:
    BN_clear_free(priv_bn);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * Compute ECDH shared secret
 * @param curve_nid OpenSSL NID
 * @param privkey Private key bytes
 * @param pk_len Private key length
 * @param peer_pubkey Peer's public key (uncompressed)
 * @param peer_len Peer public key length
 * @param shared_secret Output buffer for shared secret
 * @param ss_len Output: actual shared secret length
 * @return 0 on success, negative on error
 */
HD_OSSL_EXPORT
int32_t hd_ossl_ecdh_compute(int curve_nid,
                             const uint8_t* privkey, size_t pk_len,
                             const uint8_t* peer_pubkey, size_t peer_len,
                             uint8_t* shared_secret, size_t* ss_len) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *priv_pkey = NULL;
    EVP_PKEY *peer_pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *priv_bn = NULL;
    const char *curve_name = NULL;
    int ret = -1;

    if (curve_nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
    } else if (curve_nid == NID_secp384r1) {
        curve_name = "P-384";
    } else {
        return -1;
    }

    // Build private key
    priv_bn = BN_bin2bn(privkey, (int)pk_len, NULL);
    if (priv_bn == NULL) goto cleanup;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto cleanup;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn)) goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &priv_pkey, EVP_PKEY_KEYPAIR, params) != 1) goto cleanup;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    OSSL_PARAM_free(params);
    params = NULL;
    OSSL_PARAM_BLD_free(bld);
    bld = NULL;

    // Build peer's public key
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto cleanup;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pubkey, peer_len)) goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) goto cleanup;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    // Perform ECDH
    pctx = EVP_PKEY_CTX_new_from_pkey(fips_libctx, priv_pkey, NULL);
    if (pctx == NULL) goto cleanup;
    if (EVP_PKEY_derive_init(pctx) != 1) goto cleanup;
    if (EVP_PKEY_derive_set_peer(pctx, peer_pkey) != 1) goto cleanup;
    if (EVP_PKEY_derive(pctx, shared_secret, ss_len) != 1) goto cleanup;

    ret = 0;

cleanup:
    BN_clear_free(priv_bn);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(priv_pkey);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
