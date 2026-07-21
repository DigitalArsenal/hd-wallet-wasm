# HD Wallet WASM - Comprehensive Hierarchical Deterministic Wallet Implementation
#
# A pure C++ implementation providing all HD wallet functionality similar to
# ShapeShift's hdwallet, compiled to WebAssembly for cross-language compatibility.
#
# Features:
#   - BIP-32/39/44/49/84 HD key derivation
#   - Multi-curve support (secp256k1, Ed25519, P-256, P-384, X25519)
#   - Multi-chain support (Bitcoin, Ethereum, Solana, Cosmos, etc.)
#   - Transaction building and signing
#   - Address generation (all formats)
#   - Hardware wallet abstraction (with WASI bridge support)
#   - FIPS-compliant mode option
#
# WASI Limitations (with warnings):
#   - USB/HID device access (requires host bridge)
#   - Network operations (requires WASI sockets or host bridge)
#   - Filesystem (requires WASI filesystem capability)
#   - Random number generation (requires entropy injection)
#
# Usage:
#   emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON
#   cmake --build build --target hd_wallet_wasm
#
# Targets:
#   hd_wallet_wasm     - WASI standalone module
#   hd_wallet_wasm_js  - JavaScript ES6 module
#   hd_wallet_wasm_npm - NPM package

cmake_minimum_required(VERSION 3.16...3.28)

# Version
set(HD_WALLET_VERSION_MAJOR 2)
set(HD_WALLET_VERSION_MINOR 0)
set(HD_WALLET_VERSION_PATCH 22)

project(HDWalletWasm
  VERSION ${HD_WALLET_VERSION_MAJOR}.${HD_WALLET_VERSION_MINOR}.${HD_WALLET_VERSION_PATCH}
  LANGUAGES C CXX
  DESCRIPTION "HD Wallet WASM - Comprehensive BIP-32/39/44 implementation"
)

# Options
option(HD_WALLET_BUILD_WASM "Build WebAssembly module" OFF)
option(HD_WALLET_BUILD_TESTS "Build tests" ON)
option(HD_WALLET_USE_CRYPTOPP "Use Crypto++ for cryptographic operations" ON)
option(HD_WALLET_USE_OPENSSL "Use OpenSSL for FIPS-approved algorithms" ON)
option(HD_WALLET_FIPS_MODE "Enable FIPS-compliant mode" OFF)
option(HD_WALLET_ENABLE_BITCOIN "Enable Bitcoin support" ON)
option(HD_WALLET_ENABLE_ETHEREUM "Enable Ethereum support" ON)
option(HD_WALLET_ENABLE_COSMOS "Enable Cosmos/Tendermint support" ON)
option(HD_WALLET_ENABLE_SOLANA "Enable Solana support" ON)
option(HD_WALLET_ENABLE_POLKADOT "Enable Polkadot support" ON)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# =============================================================================
# Crypto++ Dependency
# =============================================================================

if(HD_WALLET_USE_CRYPTOPP)
  include(FetchContent)
  # SECURITY FIX [CRIT-04]: Pin to specific commit SHA instead of tag
  # Tags can be force-pushed with malicious code; commit SHAs are immutable.
  # This is the commit for CRYPTOPP_8_9_0 tag, verified 2026-02-03
  FetchContent_Declare(
    cryptopp-cmake
    GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
    GIT_TAG        604d3df147e7b16fb7caa70e22c54c9a40ac1bd5  # CRYPTOPP_8_9_0
    GIT_SHALLOW    TRUE
  )
  set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(CRYPTOPP_INSTALL OFF CACHE BOOL "" FORCE)

  if(EMSCRIPTEN)
    # Disable assembly for WASM builds
    set(CRYPTOPP_DISABLE_ASM ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_DISABLE_SSSE3 ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_DISABLE_AESNI ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "" FORCE)
  endif()

  FetchContent_MakeAvailable(cryptopp-cmake)
  add_definitions(-DHD_WALLET_USE_CRYPTOPP=1)
  message(STATUS "Using Crypto++ for cryptographic operations")
endif()

# =============================================================================
# OpenSSL FIPS Backend (Optional)
# =============================================================================

if(HD_WALLET_USE_OPENSSL)
  if(EMSCRIPTEN)
    # For WASM builds, use pre-built OpenSSL from openssl-fips/dist
    set(OPENSSL_FIPS_DIR "${CMAKE_SOURCE_DIR}/openssl-fips/dist")
    if(EXISTS "${OPENSSL_FIPS_DIR}/lib/libcrypto.a")
      message(STATUS "Using OpenSSL FIPS from ${OPENSSL_FIPS_DIR}")
      set(OPENSSL_FIPS_INCLUDE "${OPENSSL_FIPS_DIR}/include")
      set(OPENSSL_FIPS_LIB "${OPENSSL_FIPS_DIR}/lib/libcrypto.a")
      add_definitions(-DHD_WALLET_USE_OPENSSL=1)
    else()
      message(WARNING "OpenSSL FIPS not found. Run openssl-fips/build.sh first.")
      message(WARNING "Falling back to Crypto++ only.")
      set(HD_WALLET_USE_OPENSSL OFF)
    endif()
  else()
    # For native builds, use system OpenSSL
    find_package(OpenSSL 3.0)
    if(OpenSSL_FOUND)
      message(STATUS "Using system OpenSSL ${OPENSSL_VERSION}")
      add_definitions(-DHD_WALLET_USE_OPENSSL=1)
    else()
      message(WARNING "OpenSSL 3.0+ not found. Falling back to Crypto++ only.")
      set(HD_WALLET_USE_OPENSSL OFF)
    endif()
  endif()
endif()

# =============================================================================
# Source Files
# =============================================================================

set(HD_WALLET_HEADERS
  # Core
  include/hd_wallet/config.h
  include/hd_wallet/types.h
  include/hd_wallet/error.h
  include/hd_wallet/utils.h
  include/hd_wallet/secure_memory.h
  include/hd_wallet/password_profile.h
  include/hd_wallet/sdn_identity.h
  # BIP Standards
  include/hd_wallet/bip39.h
  include/hd_wallet/bip32.h
  include/hd_wallet/bip44.h
  include/hd_wallet/slip44.h
  # Cryptography
  include/hd_wallet/curves.h
  include/hd_wallet/hash.h
  include/hd_wallet/ecdsa.h
  include/hd_wallet/eddsa.h
  include/hd_wallet/ecdh.h
  include/hd_wallet/libp2p.h
  include/hd_wallet/x509.h
  # Coins/Chains
  include/hd_wallet/coins/coin.h
  include/hd_wallet/coins/bitcoin.h
  include/hd_wallet/coins/ethereum.h
  include/hd_wallet/coins/cosmos.h
  include/hd_wallet/coins/solana.h
  include/hd_wallet/coins/polkadot.h
  # Transactions
  include/hd_wallet/tx/transaction.h
  include/hd_wallet/tx/bitcoin_tx.h
  include/hd_wallet/tx/ethereum_tx.h
  # Hardware Wallet Abstraction
  include/hd_wallet/hw/hw_wallet.h
  include/hd_wallet/hw/hw_transport.h
  include/hd_wallet/hw/keepkey.h
  include/hd_wallet/hw/trezor.h
  include/hd_wallet/hw/ledger.h
  # Keyring and Key Manager
  include/hd_wallet/keyring.h
  include/hd_wallet/key_manager.h
  # WASI
  include/hd_wallet/wasi_bridge.h
  # Aligned Binary API
  include/hd_wallet/aligned_api.h
)

set(HD_WALLET_SOURCES
  # Core
  src/utils.cpp
  src/secure_memory.cpp
  src/error.cpp
  src/password_profile.cpp
  src/sdn_identity.cpp
  src/sdn_identity_secrets.cpp
  src/canonical_json.cpp
  # BIP Standards
  src/bip39.cpp
  src/bip32.cpp
  src/bip44.cpp
  # Cryptography
  src/curves.cpp
  src/hash.cpp
  src/ecdsa.cpp
  src/eddsa.cpp
  src/ecdh.cpp
  src/ecies.cpp
  src/x509.cpp
  src/libp2p.cpp
  # Coins
  src/coins/coin.cpp
  src/coins/bitcoin.cpp
  src/coins/ethereum.cpp
  src/coins/cosmos.cpp
  src/coins/solana.cpp
  src/coins/polkadot.cpp
  # Transactions
  src/tx/transaction.cpp
  src/tx/bitcoin_tx.cpp
  src/tx/ethereum_tx.cpp
  # Hardware Wallet Abstraction
  src/hw/hw_wallet.cpp
  src/hw/hw_transport.cpp
  src/hw/keepkey.cpp
  src/hw/trezor.cpp
  src/hw/ledger.cpp
  # Keyring and Key Manager
  src/keyring.cpp
  src/key_manager.cpp
  # WASI Bridge
  src/wasi_bridge.cpp
  # Aligned Binary API
  src/aligned_api.cpp
)

# =============================================================================
# Static Library (for native builds and linking)
# =============================================================================

if(NOT EMSCRIPTEN)
  add_library(hd_wallet STATIC ${HD_WALLET_SOURCES})
  target_include_directories(hd_wallet
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned>
      $<INSTALL_INTERFACE:include>
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/generated
  )
  target_compile_features(hd_wallet PUBLIC cxx_std_20)

  if(HD_WALLET_BUILD_TESTS)
    target_compile_definitions(hd_wallet PRIVATE
      HD_WALLET_PASSWORD_PROFILE_TESTING=1
      HD_WALLET_SDN_IDENTITY_TESTING=1
    )
  endif()

  if(HD_WALLET_USE_CRYPTOPP)
    target_link_libraries(hd_wallet PUBLIC cryptopp)
  endif()

  # OpenSSL backend for native builds
  if(HD_WALLET_USE_OPENSSL AND OpenSSL_FOUND)
    target_sources(hd_wallet PRIVATE src/crypto_openssl.c)
    target_link_libraries(hd_wallet PUBLIC OpenSSL::Crypto)
  endif()

  # macOS requires Security framework for SecRandomCopyBytes
  if(APPLE AND NOT EMSCRIPTEN)
    target_link_libraries(hd_wallet PUBLIC "-framework Security")
  endif()

  if(HD_WALLET_FIPS_MODE)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_FIPS_MODE=1)
  endif()

  # Chain-specific flags
  if(HD_WALLET_ENABLE_BITCOIN)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_BITCOIN=1)
  endif()
  if(HD_WALLET_ENABLE_ETHEREUM)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_ETHEREUM=1)
  endif()
  if(HD_WALLET_ENABLE_COSMOS)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_COSMOS=1)
  endif()
  if(HD_WALLET_ENABLE_SOLANA)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_SOLANA=1)
  endif()
  if(HD_WALLET_ENABLE_POLKADOT)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_POLKADOT=1)
  endif()
endif()

# =============================================================================
# WASM Build
# =============================================================================

if(HD_WALLET_BUILD_WASM OR EMSCRIPTEN)
  message(STATUS "")
  message(STATUS "=== HD Wallet WASM Build ===")
  message(STATUS "")

  set(WASM_OUTPUT_DIR "${CMAKE_BINARY_DIR}/wasm" CACHE PATH "WASM output directory")
  set(WASM_NPM_DIR "${CMAKE_SOURCE_DIR}/wasm/dist" CACHE PATH "NPM package output directory")

  file(MAKE_DIRECTORY "${WASM_OUTPUT_DIR}")
  file(MAKE_DIRECTORY "${WASM_NPM_DIR}")

  if(EMSCRIPTEN)
    # WASM source files - core + coin address functionality
    # wasm_exports.cpp contains unique C wrappers for hash/KDF/curve functions
    # that are not already exported from the main library source files.
    set(HD_WALLET_WASM_SOURCES
      src/utils.cpp
      src/secure_memory.cpp
      src/error.cpp
      src/bip39.cpp
      src/bip32.cpp
      src/bip44.cpp
      src/curves.cpp
      src/hash.cpp
      src/ecdsa.cpp
      src/eddsa.cpp
      src/ecdh.cpp
      src/ecies.cpp
      src/x509.cpp
      src/wasi_bridge.cpp
      src/aligned_api.cpp
      src/wasm_exports.cpp
      generated/sdn/plugin_manifest_exports.cpp
      # Transaction building
      src/tx/transaction.cpp
      src/tx/bitcoin_tx.cpp
      src/tx/ethereum_tx.cpp
      # Coin address generation and validation
      src/coins/coin.cpp
      src/coins/bitcoin.cpp
      src/coins/ethereum.cpp
      src/coins/solana.cpp
      src/coins/cosmos.cpp
      src/coins/polkadot.cpp
      # libp2p PeerID / IPNS
      src/libp2p.cpp
    )

    # Add OpenSSL wrapper when enabled
    if(HD_WALLET_USE_OPENSSL)
      list(APPEND HD_WALLET_WASM_SOURCES src/crypto_openssl.c)
    endif()

    # ==========================================================================
    # Exported Functions - Core API for Go/WASI integration
    # Only includes functions that are actually implemented in the minimal build
    # ==========================================================================

    set(WASM_EXPORTED_FUNCTIONS
      # ========== Memory Management ==========
      "_malloc"
      "_free"
      "_hd_alloc"
      "_hd_dealloc"
      "_hd_secure_wipe"

      # ========== Module Info ==========
      "_hd_get_version"
      "_hd_get_version_string"
      "_hd_has_cryptopp"
      "_hd_is_fips_mode"
      "_plugin_get_manifest_flatbuffer"
      "_plugin_get_manifest_flatbuffer_size"

      # ========== WASI Bridge ==========
      "_hd_wasi_has_feature"
      "_hd_wasi_get_warning"

      # ========== Entropy ==========
      "_hd_inject_entropy"
      "_hd_get_entropy_status"

      # ========== BIP-39 Mnemonic ==========
      "_hd_mnemonic_generate"
      "_hd_mnemonic_validate"
      "_hd_mnemonic_to_seed"
      "_hd_mnemonic_to_entropy"
      "_hd_entropy_to_mnemonic"
      "_hd_mnemonic_get_wordlist"
      "_hd_mnemonic_suggest_word"
      "_hd_mnemonic_check_word"

      # ========== BIP-32 HD Keys ==========
      "_hd_key_from_seed"
      "_hd_key_from_xprv"
      "_hd_key_from_xpub"
      "_hd_key_derive_path"
      "_hd_key_derive_child"
      "_hd_key_derive_hardened"
      "_hd_key_get_private"
      "_hd_key_get_public"
      "_hd_key_get_chain_code"
      "_hd_key_get_fingerprint"
      "_hd_key_get_parent_fingerprint"
      "_hd_key_get_depth"
      "_hd_key_get_child_index"
      "_hd_key_serialize_xprv"
      "_hd_key_serialize_xpub"
      "_hd_key_neutered"
      "_hd_key_is_neutered"
      "_hd_key_wipe"
      "_hd_key_clone"
      "_hd_key_destroy"

      # ========== BIP-44 Paths ==========
      "_hd_path_build"
      "_hd_path_parse"

      # ========== Curve Operations (Generic) ==========
      "_hd_curve_pubkey_from_privkey"
      "_hd_curve_decompress_pubkey"
      "_hd_curve_compress_pubkey"

      # ========== secp256k1 Signing ==========
      "_hd_secp256k1_sign"
      "_hd_secp256k1_sign_recoverable"
      "_hd_secp256k1_recover"
      "_hd_secp256k1_verify"
      "_hd_ecdh_secp256k1"

      # ========== Generic ECDH ==========
      "_hd_ecdh"

      # ========== Ed25519 ==========
      "_hd_ed25519_sign"
      "_hd_ed25519_verify"
      "_hd_ed25519_pubkey_from_seed"

      # ========== X25519 ECDH ==========
      "_hd_ecdh_x25519"
      "_hd_x25519_pubkey"

      # ========== P-256 (NIST) ==========
      "_hd_p256_sign"
      "_hd_p256_verify"
      "_hd_ecdh_p256"

      # ========== P-384 (NIST) ==========
      "_hd_p384_sign"
      "_hd_p384_verify"
      "_hd_ecdh_p384"

      # ========== Hash Functions ==========
      "_hd_hash_sha256"
      "_hd_hash_sha512"
      "_hd_hash_keccak256"
      "_hd_hash_ripemd160"
      "_hd_hash_hash160"
      "_hd_hash_blake2b"
      "_hd_hash_blake2s"

      # ========== Key Derivation Functions ==========
      "_hd_kdf_hkdf"
      "_hd_kdf_pbkdf2"
      "_hd_kdf_scrypt"

      # ========== X.509 ==========
      "_hd_x509_generate_private_key"
      "_hd_x509_export_private_key_pem"
      "_hd_x509_import_private_key_pem"
      "_hd_x509_create_self_signed"
      "_hd_x509_issue_certificate"
      "_hd_x509_convert_certificate"
      "_hd_x509_parse_certificate_json"
      "_hd_x509_verify_wallet_attestation"
      "_hd_x509_export_pkcs12"
      "_hd_x509_import_pkcs12_json"

      # ========== SLIP-10 Key Derivation ==========
      "_hd_slip10_ed25519_derive_path"

      # ========== Aligned Binary API ==========
      "_hd_aligned_derive_batch"
      "_hd_aligned_sign_batch"
      "_hd_aligned_verify_batch"
      "_hd_aligned_stream_create"
      "_hd_aligned_stream_next"
      "_hd_aligned_stream_status"
      "_hd_aligned_stream_destroy"
      "_hd_aligned_from_extended_key"
      "_hd_aligned_to_extended_key"
      "_hd_aligned_derived_key_entry_size"
      "_hd_aligned_signature_entry_size"
      "_hd_aligned_extended_key_data_size"
      "_hd_aligned_batch_derive_request_size"

      # ========== AES-GCM Encryption ==========
      "_hd_aes_gcm_encrypt"
      "_hd_aes_gcm_decrypt"

      # ========== ECIES ==========
      "_hd_ecies_encrypt"
      "_hd_ecies_decrypt"
      "_hd_ecies_overhead"
      # ========== AES-CTR ==========
      "_hd_aes_ctr_encrypt"
      "_hd_aes_ctr_decrypt"

      # ========== Coin Address Generation & Validation ==========
      # Generic coin utilities (coin.cpp)
      "_hd_coin_address_from_pubkey"
      "_hd_coin_validate_address"
      "_hd_coin_sign_message"
      "_hd_coin_verify_message"
      "_hd_base58_encode"
      "_hd_base58_decode"
      "_hd_base58check_encode"
      "_hd_base58check_decode"
      "_hd_bech32_encode"
      "_hd_bech32_decode"
      # Bitcoin (bitcoin.cpp)
      "_hd_btc_p2pkh_address"
      "_hd_btc_p2sh_address"
      "_hd_btc_p2wpkh_address"
      "_hd_btc_p2wsh_address"
      "_hd_btc_p2tr_address"
      "_hd_btc_validate_address"
      "_hd_btc_detect_address_type"
      "_hd_btc_decode_address"
      "_hd_btc_sign_message"
      "_hd_btc_verify_message"
      "_hd_btc_to_wif"
      "_hd_btc_from_wif"
      # Bitcoin Transactions (tx/bitcoin_tx.cpp)
      "_hd_btc_tx_create"
      "_hd_btc_tx_create_v"
      "_hd_btc_tx_add_input"
      "_hd_btc_tx_add_output"
      "_hd_btc_tx_add_p2pkh_output"
      "_hd_btc_tx_add_p2wpkh_output"
      "_hd_btc_tx_sign"
      "_hd_btc_tx_sign_input"
      "_hd_btc_tx_serialize"
      "_hd_btc_tx_get_txid"
      "_hd_btc_tx_get_txid_hex"
      "_hd_btc_tx_get_size"
      "_hd_btc_tx_get_vsize"
      "_hd_btc_tx_get_weight"
      "_hd_btc_tx_get_fee"
      "_hd_btc_tx_validate"
      "_hd_btc_tx_destroy"
      "_hd_btc_tx_parse"
      "_hd_btc_tx_parse_hex"
      # Ethereum (ethereum.cpp)
      "_hd_eth_address"
      "_hd_eth_validate_address"
      "_hd_eth_checksum_address"
      "_hd_eth_verify_checksum"
      "_hd_eth_sign_message"
      "_hd_eth_verify_message"
      "_hd_eth_recover_address"
      "_hd_eth_hash_message"
      "_hd_eth_sign_typed_data"
      # Ethereum Transactions (tx/ethereum_tx.cpp)
      "_hd_eth_tx_create"
      "_hd_eth_tx_create_eip1559"
      "_hd_eth_tx_set_nonce"
      "_hd_eth_tx_set_gas_price"
      "_hd_eth_tx_set_gas_limit"
      "_hd_eth_tx_set_to"
      "_hd_eth_tx_set_to_hex"
      "_hd_eth_tx_set_value"
      "_hd_eth_tx_set_value_256"
      "_hd_eth_tx_set_data"
      "_hd_eth_tx_sign"
      "_hd_eth_tx_serialize"
      "_hd_eth_tx_get_hash"
      "_hd_eth_tx_get_hash_hex"
      "_hd_eth_tx_get_sender"
      "_hd_eth_tx_get_size"
      "_hd_eth_tx_get_max_fee"
      "_hd_eth_tx_validate"
      "_hd_eth_tx_destroy"
      "_hd_eth_tx_parse"
      "_hd_eth_tx_parse_hex"
      # Solana (solana.cpp)
      "_hd_sol_address"
      "_hd_sol_validate_address"
      "_hd_sol_address_to_pubkey"
      "_hd_sol_sign_message"
      "_hd_sol_verify_message"
      "_hd_sol_derive_pubkey"
      "_hd_sol_find_pda"
      "_hd_sol_get_associated_token_address"
      # Cosmos (cosmos.cpp)
      "_hd_cosmos_address"
      "_hd_cosmos_validate_address"
      "_hd_cosmos_convert_prefix"
      "_hd_cosmos_sign_amino"
      "_hd_cosmos_sign_direct"
      "_hd_cosmos_verify_signature"
      "_hd_cosmos_sign_arbitrary"
      # Polkadot/Substrate (polkadot.cpp)
      "_hd_dot_address"
      "_hd_dot_validate_address"
      "_hd_dot_decode_address"
      "_hd_dot_convert_prefix"
      "_hd_dot_sign_message"
      "_hd_dot_verify_message"
      "_hd_dot_sign_extrinsic"
      "_hd_dot_derive_pubkey"
      # libp2p PeerID / IPNS (libp2p.cpp)
      "_hd_libp2p_peer_id"
      "_hd_libp2p_peer_id_string"
      "_hd_libp2p_ipns_hash"
      "_hd_libp2p_ipns_hash_base32"
      "_hd_encode_base32lower"
      "_hd_encode_base36lower"
    )

    # Add OpenSSL FIPS exports only when OpenSSL is enabled
    if(HD_WALLET_USE_OPENSSL)
      list(APPEND WASM_EXPORTED_FUNCTIONS
        "_hd_openssl_init_fips"
        "_hd_openssl_init_default"
        "_hd_openssl_cleanup"
        "_hd_openssl_is_fips"
      )
    endif()
    string(JOIN "," EXPORTED_FUNCS_STR ${WASM_EXPORTED_FUNCTIONS})

    set(BROWSER_EXPORTED_FUNCTIONS
      ${WASM_EXPORTED_FUNCTIONS}
      "_hd_sdn_derive_password_identity"
      "_hd_sdn_derive_legacy_password_identity"
      "_hd_sdn_import_legacy_mnemonic_identity"
      "_hd_sdn_import_remembered_identity"
      "_hd_sdn_sign_login_v1"
      "_hd_sdn_sign_login_v2"
      "_hd_sdn_sign_asset_review_authority_activation"
      "_hd_sdn_sign_asset_review_decision"
      "_hd_sdn_seal_remembered_identity"
      "_hd_sdn_destroy_identity"
    )
    string(JOIN "," BROWSER_EXPORTED_FUNCS_STR ${BROWSER_EXPORTED_FUNCTIONS})

    # =========================================================================
    # libsecp256k1 - Bitcoin Core's secp256k1 (replaces Crypto++ EC in WASM)
    # Crypto++ ECP::ScalarMultiply is unreliable in 32-bit WASM due to
    # exception handling being disabled (-fignore-exceptions).
    # =========================================================================
    include(FetchContent)
    FetchContent_Declare(
      secp256k1
      GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
      GIT_TAG        1a53f4961f337b4d166c25fce72ef0dc88806618  # v0.7.1
      GIT_SHALLOW    TRUE
    )
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
    set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ASM "OFF" CACHE STRING "" FORCE)
    FetchContent_MakeAvailable(secp256k1)
    message(STATUS "Using libsecp256k1 for WASM EC operations")

    # WASM compile options
    set(WASM_COMPILE_OPTIONS
      -DHD_WALLET_WASM=1
      -DHD_WALLET_USE_CRYPTOPP=1
      -DHD_WALLET_USE_LIBSECP256K1=1
    )

    if(HD_WALLET_FIPS_MODE)
      list(APPEND WASM_COMPILE_OPTIONS -DHD_WALLET_FIPS_MODE=1)
    endif()

    # Chain-specific flags
    list(APPEND WASM_COMPILE_OPTIONS
      -DHD_WALLET_ENABLE_BITCOIN=1
      -DHD_WALLET_ENABLE_ETHEREUM=1
      -DHD_WALLET_ENABLE_COSMOS=1
      -DHD_WALLET_ENABLE_SOLANA=1
      -DHD_WALLET_ENABLE_POLKADOT=1
    )

    # =========================================================================
    # Target: WASI standalone module (for Go, Rust, Python via WASI runtimes)
    # =========================================================================
    add_executable(hd_wallet_wasm ${HD_WALLET_WASM_SOURCES})
    target_include_directories(hd_wallet_wasm PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
      $<$<BOOL:${HD_WALLET_USE_OPENSSL}>:${OPENSSL_FIPS_INCLUDE}>
    )
    # Build with exceptions enabled but trap on throw
    # This allows Crypto++ to compile but will abort if an exception is thrown
    # -fignore-exceptions tells the compiler to ignore try/catch blocks (no-op)
    target_compile_options(hd_wallet_wasm PRIVATE ${WASM_COMPILE_OPTIONS} -fignore-exceptions)
    target_link_libraries(hd_wallet_wasm PRIVATE cryptopp secp256k1)
    if(HD_WALLET_USE_OPENSSL AND EXISTS "${OPENSSL_FIPS_LIB}")
      target_link_libraries(hd_wallet_wasm PRIVATE "${OPENSSL_FIPS_LIB}")
    endif()
    set_target_properties(hd_wallet_wasm PROPERTIES
      OUTPUT_NAME "hd-wallet"
      SUFFIX ".wasm"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm PRIVATE
      -sSTANDALONE_WASM=1
      -sPURE_WASI=1
      -sWASM=1
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCS_STR}]"
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sDISABLE_EXCEPTION_CATCHING=1
      -fignore-exceptions
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: Pure WASI module (for Go/wazero, Rust/wasmtime, Python/wasmer)
    # This build disables C++ exceptions for true WASI compatibility
    # =========================================================================
    # WASI sources: hardened set with full Crypto++ security features + tx support
    set(HD_WALLET_WASI_SOURCES
      src/utils.cpp
      src/secure_memory.cpp
      src/error.cpp
      src/bip39.cpp
      src/bip32.cpp
      src/bip44.cpp
      src/curves.cpp
      src/hash.cpp
      src/ecdsa.cpp
      src/eddsa.cpp
      src/ecdh.cpp
      src/ecies.cpp
      src/wasi_bridge.cpp
      src/wasm_exports.cpp
      generated/sdn/plugin_manifest_exports.cpp
      src/coins/coin.cpp
      src/coins/bitcoin.cpp
      src/coins/ethereum.cpp
      src/coins/solana.cpp
      src/coins/cosmos.cpp
      src/coins/polkadot.cpp
      src/libp2p.cpp
      src/tx/transaction.cpp
      src/tx/bitcoin_tx.cpp
      src/tx/ethereum_tx.cpp
    )

    # Add OpenSSL wrapper to WASI when FIPS enabled
    if(HD_WALLET_USE_OPENSSL)
      list(APPEND HD_WALLET_WASI_SOURCES src/crypto_openssl.c)
    endif()

    # WASI exports: core + coin + tx support (no aligned, keyring, key_manager, hw)
    set(WASI_EXPORTED_FUNCTIONS
      # Memory Management
      "_malloc"
      "_free"
      "_hd_alloc"
      "_hd_dealloc"
      "_hd_secure_dealloc"
      "_hd_secure_wipe"
      # Module Info
      "_hd_get_version"
      "_hd_get_version_string"
      "_hd_has_cryptopp"
      "_hd_is_fips_mode"
      "_plugin_get_manifest_flatbuffer"
      "_plugin_get_manifest_flatbuffer_size"
      "_hd_get_supported_coins"
      "_hd_get_supported_curves"
      # WASI Bridge
      "_hd_wasi_has_feature"
      "_hd_wasi_get_warning"
      # Entropy
      "_hd_inject_entropy"
      "_hd_get_entropy_status"
      # BIP-39 Mnemonic
      "_hd_mnemonic_generate"
      "_hd_mnemonic_validate"
      "_hd_mnemonic_to_seed"
      "_hd_mnemonic_to_entropy"
      "_hd_entropy_to_mnemonic"
      "_hd_mnemonic_get_wordlist"
      "_hd_mnemonic_suggest_word"
      "_hd_mnemonic_check_word"
      # BIP-32 HD Keys
      "_hd_key_from_seed"
      "_hd_key_from_xprv"
      "_hd_key_from_xpub"
      "_hd_key_derive_path"
      "_hd_key_derive_child"
      "_hd_key_derive_hardened"
      "_hd_key_get_private"
      "_hd_key_get_public"
      "_hd_key_get_chain_code"
      "_hd_key_get_fingerprint"
      "_hd_key_get_parent_fingerprint"
      "_hd_key_get_depth"
      "_hd_key_get_child_index"
      "_hd_key_serialize_xprv"
      "_hd_key_serialize_xpub"
      "_hd_key_neutered"
      "_hd_key_is_neutered"
      "_hd_key_wipe"
      "_hd_key_clone"
      "_hd_key_destroy"
      # BIP-44/49/84 Paths
      "_hd_path_build"
      "_hd_path_parse"
      # Multi-Curve Keys
      "_hd_curve_pubkey_from_privkey"
      "_hd_curve_decompress_pubkey"
      # ECDSA Signing (secp256k1)
      "_hd_secp256k1_sign"
      "_hd_secp256k1_verify"
      # EdDSA Signing (Ed25519)
      "_hd_ed25519_sign"
      "_hd_ed25519_verify"
      "_hd_ed25519_pubkey_from_seed"
      # SLIP-10 Ed25519 Derivation
      "_hd_slip10_ed25519_derive_path"
      # ECDSA Signing (P-256/P-384)
      "_hd_p256_sign"
      "_hd_p256_verify"
      "_hd_p384_sign"
      "_hd_p384_verify"
      # ECDH Key Exchange
      "_hd_ecdh_secp256k1"
      "_hd_ecdh_p256"
      "_hd_ecdh_p384"
      "_hd_ecdh_x25519"
      "_hd_x25519_pubkey"
      # ECIES
      "_hd_ecies_encrypt"
      "_hd_ecies_decrypt"
      "_hd_ecies_overhead"
      # AES-CTR
      "_hd_aes_ctr_encrypt"
      "_hd_aes_ctr_decrypt"
      # Hash Functions
      "_hd_hash_sha256"
      "_hd_hash_sha512"
      "_hd_hash_keccak256"
      "_hd_hash_ripemd160"
      "_hd_hash_hash160"
      "_hd_hash_blake2b"
      "_hd_hash_blake2s"
      # Key Derivation
      "_hd_kdf_hkdf"
      "_hd_kdf_pbkdf2"
      "_hd_kdf_scrypt"
      # Coin Address Generation & Validation
      # Generic coin utilities (coin.cpp)
      "_hd_coin_address_from_pubkey"
      "_hd_coin_validate_address"
      "_hd_coin_sign_message"
      "_hd_coin_verify_message"
      "_hd_base58_encode"
      "_hd_base58_decode"
      "_hd_base58check_encode"
      "_hd_base58check_decode"
      "_hd_bech32_encode"
      "_hd_bech32_decode"
      # Bitcoin (bitcoin.cpp)
      "_hd_btc_p2pkh_address"
      "_hd_btc_p2sh_address"
      "_hd_btc_p2wpkh_address"
      "_hd_btc_p2wsh_address"
      "_hd_btc_p2tr_address"
      "_hd_btc_validate_address"
      "_hd_btc_detect_address_type"
      "_hd_btc_decode_address"
      "_hd_btc_sign_message"
      "_hd_btc_verify_message"
      "_hd_btc_to_wif"
      "_hd_btc_from_wif"
      # Bitcoin Transactions (tx/bitcoin_tx.cpp)
      "_hd_btc_tx_create"
      "_hd_btc_tx_create_v"
      "_hd_btc_tx_add_input"
      "_hd_btc_tx_add_output"
      "_hd_btc_tx_add_p2pkh_output"
      "_hd_btc_tx_add_p2wpkh_output"
      "_hd_btc_tx_sign"
      "_hd_btc_tx_sign_input"
      "_hd_btc_tx_serialize"
      "_hd_btc_tx_get_txid"
      "_hd_btc_tx_get_txid_hex"
      "_hd_btc_tx_get_size"
      "_hd_btc_tx_get_vsize"
      "_hd_btc_tx_get_weight"
      "_hd_btc_tx_get_fee"
      "_hd_btc_tx_validate"
      "_hd_btc_tx_destroy"
      "_hd_btc_tx_parse"
      "_hd_btc_tx_parse_hex"
      # Ethereum (ethereum.cpp)
      "_hd_eth_address"
      "_hd_eth_validate_address"
      "_hd_eth_checksum_address"
      "_hd_eth_verify_checksum"
      "_hd_eth_sign_message"
      "_hd_eth_verify_message"
      "_hd_eth_recover_address"
      "_hd_eth_hash_message"
      "_hd_eth_sign_typed_data"
      # Ethereum Transactions (tx/ethereum_tx.cpp)
      "_hd_eth_tx_create"
      "_hd_eth_tx_create_eip1559"
      "_hd_eth_tx_set_nonce"
      "_hd_eth_tx_set_gas_price"
      "_hd_eth_tx_set_gas_limit"
      "_hd_eth_tx_set_to"
      "_hd_eth_tx_set_to_hex"
      "_hd_eth_tx_set_value"
      "_hd_eth_tx_set_value_256"
      "_hd_eth_tx_set_data"
      "_hd_eth_tx_sign"
      "_hd_eth_tx_serialize"
      "_hd_eth_tx_get_hash"
      "_hd_eth_tx_get_hash_hex"
      "_hd_eth_tx_get_sender"
      "_hd_eth_tx_get_size"
      "_hd_eth_tx_get_max_fee"
      "_hd_eth_tx_validate"
      "_hd_eth_tx_destroy"
      "_hd_eth_tx_parse"
      "_hd_eth_tx_parse_hex"
      # Solana (solana.cpp)
      "_hd_sol_address"
      "_hd_sol_validate_address"
      "_hd_sol_address_to_pubkey"
      "_hd_sol_sign_message"
      "_hd_sol_verify_message"
      "_hd_sol_derive_pubkey"
      "_hd_sol_find_pda"
      "_hd_sol_get_associated_token_address"
      # Cosmos (cosmos.cpp)
      "_hd_cosmos_address"
      "_hd_cosmos_validate_address"
      "_hd_cosmos_convert_prefix"
      "_hd_cosmos_sign_amino"
      "_hd_cosmos_sign_direct"
      "_hd_cosmos_verify_signature"
      "_hd_cosmos_sign_arbitrary"
      # Polkadot/Substrate (polkadot.cpp)
      "_hd_dot_address"
      "_hd_dot_validate_address"
      "_hd_dot_decode_address"
      "_hd_dot_convert_prefix"
      "_hd_dot_sign_message"
      "_hd_dot_verify_message"
      "_hd_dot_sign_extrinsic"
      "_hd_dot_derive_pubkey"
      # libp2p PeerID / IPNS (libp2p.cpp)
      "_hd_libp2p_peer_id"
      "_hd_libp2p_peer_id_string"
      "_hd_libp2p_ipns_hash"
      "_hd_libp2p_ipns_hash_base32"
      "_hd_encode_base32lower"
      "_hd_encode_base36lower"
    )
    string(JOIN "," WASI_EXPORTED_FUNCS_STR ${WASI_EXPORTED_FUNCTIONS})

    add_executable(hd_wallet_wasm_wasi ${HD_WALLET_WASI_SOURCES})
    target_include_directories(hd_wallet_wasm_wasi PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
    )
    target_compile_options(hd_wallet_wasm_wasi PRIVATE
      ${WASM_COMPILE_OPTIONS}
      -fignore-exceptions
      -DHD_WALLET_NO_EXCEPTIONS=1
      -DHD_WALLET_FORCE_WASI=1
      -DHD_WALLET_ENABLE_BITCOIN=1
      -DHD_WALLET_ENABLE_ETHEREUM=1
      -DHD_WALLET_ENABLE_SOLANA=1
    )
    target_include_directories(hd_wallet_wasm_wasi PRIVATE
      $<$<BOOL:${HD_WALLET_USE_OPENSSL}>:${OPENSSL_FIPS_INCLUDE}>
    )
    target_link_libraries(hd_wallet_wasm_wasi PRIVATE cryptopp secp256k1)
    if(HD_WALLET_USE_OPENSSL AND EXISTS "${OPENSSL_FIPS_LIB}")
      target_link_libraries(hd_wallet_wasm_wasi PRIVATE "${OPENSSL_FIPS_LIB}")
    endif()
    set_target_properties(hd_wallet_wasm_wasi PROPERTIES
      OUTPUT_NAME "hd-wallet-wasi"
      SUFFIX ".wasm"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm_wasi PRIVATE
      -sSTANDALONE_WASM=1
      -sPURE_WASI=1
      -sWASM=1
      -sERROR_ON_UNDEFINED_SYMBOLS=1
      -sNO_FILESYSTEM=1
      "-sEXPORTED_FUNCTIONS=[${WASI_EXPORTED_FUNCS_STR}]"
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -fignore-exceptions
      -sDISABLE_EXCEPTION_CATCHING=1
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: JavaScript ES6 module (browsers and Node.js)
    # =========================================================================
    add_executable(hd_wallet_wasm_js ${HD_WALLET_WASM_SOURCES})
    target_sources(hd_wallet_wasm_js PRIVATE
      src/password_profile.cpp
      src/sdn_identity.cpp
      src/sdn_identity_secrets.cpp
      src/canonical_json.cpp
    )
    target_include_directories(hd_wallet_wasm_js PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
      $<$<BOOL:${HD_WALLET_USE_OPENSSL}>:${OPENSSL_FIPS_INCLUDE}>
    )
    target_compile_features(hd_wallet_wasm_js PRIVATE cxx_std_20)
    target_compile_definitions(hd_wallet_wasm_js PRIVATE
      HD_WALLET_SDN_TYPED_API=1
    )
    target_compile_options(hd_wallet_wasm_js PRIVATE ${WASM_COMPILE_OPTIONS} -fexceptions)
    target_link_libraries(hd_wallet_wasm_js PRIVATE cryptopp secp256k1)
    if(HD_WALLET_USE_OPENSSL AND EXISTS "${OPENSSL_FIPS_LIB}")
      target_link_libraries(hd_wallet_wasm_js PRIVATE "${OPENSSL_FIPS_LIB}")
    endif()
    set_target_properties(hd_wallet_wasm_js PROPERTIES
      OUTPUT_NAME "hd-wallet"
      SUFFIX ".js"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}/browser"
    )
    target_link_options(hd_wallet_wasm_js PRIVATE
      -sWASM=1
      -sWASM_BIGINT=1
      -sMODULARIZE=1
      -sEXPORT_NAME=HDWalletWasm
      -sEXPORT_ES6=1
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${BROWSER_EXPORTED_FUNCS_STR}]"
      -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP32
      -sENVIRONMENT=web,worker
      -sNO_EXIT_RUNTIME=1
      -fexceptions
      -sDISABLE_EXCEPTION_THROWING=0
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: Single-file version (inlined WASM)
    # =========================================================================
    add_executable(hd_wallet_wasm_inline ${HD_WALLET_WASM_SOURCES})
    target_sources(hd_wallet_wasm_inline PRIVATE
      src/password_profile.cpp
      src/sdn_identity.cpp
      src/sdn_identity_secrets.cpp
      src/canonical_json.cpp
    )
    target_include_directories(hd_wallet_wasm_inline PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
      $<$<BOOL:${HD_WALLET_USE_OPENSSL}>:${OPENSSL_FIPS_INCLUDE}>
    )
    target_compile_features(hd_wallet_wasm_inline PRIVATE cxx_std_20)
    target_compile_definitions(hd_wallet_wasm_inline PRIVATE
      HD_WALLET_SDN_TYPED_API=1
    )
    target_compile_options(hd_wallet_wasm_inline PRIVATE ${WASM_COMPILE_OPTIONS} -fexceptions)
    target_link_libraries(hd_wallet_wasm_inline PRIVATE cryptopp secp256k1)
    if(HD_WALLET_USE_OPENSSL AND EXISTS "${OPENSSL_FIPS_LIB}")
      target_link_libraries(hd_wallet_wasm_inline PRIVATE "${OPENSSL_FIPS_LIB}")
    endif()
    set_target_properties(hd_wallet_wasm_inline PROPERTIES
      OUTPUT_NAME "hd-wallet-inline"
      SUFFIX ".js"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm_inline PRIVATE
      -sWASM=1
      -sWASM_BIGINT=1
      -sMODULARIZE=1
      -sEXPORT_NAME=HDWalletWasm
      -sEXPORT_ES6=1
      -sSINGLE_FILE=1
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${BROWSER_EXPORTED_FUNCS_STR}]"
      -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP32
      -sENVIRONMENT=web,worker
      -sNO_EXIT_RUNTIME=1
      -fexceptions
      -sDISABLE_EXCEPTION_THROWING=0
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # wasm-opt post-build optimization
    # =========================================================================
    find_program(WASM_OPT wasm-opt
      HINTS "${EMSCRIPTEN_ROOT_PATH}/../../bin"
            "${EMSCRIPTEN_ROOT_PATH}/../bin"
            "$ENV{EMSDK}/upstream/bin"
    )
    if(WASM_OPT)
      message(STATUS "Found wasm-opt: ${WASM_OPT}")
    else()
      message(WARNING "wasm-opt not found — WASM binaries will not be stripped/optimized")
    endif()

    # =========================================================================
    # Target: NPM package
    # =========================================================================
    add_custom_target(hd_wallet_wasm_npm ALL
      DEPENDS hd_wallet_wasm_inline hd_wallet_wasm_js hd_wallet_wasm_wasi
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WASM_OUTPUT_DIR}/hd-wallet-inline.js"
        "${WASM_NPM_DIR}/hd-wallet.js"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WASM_OUTPUT_DIR}/browser/hd-wallet.wasm"
        "${WASM_NPM_DIR}/hd-wallet.wasm"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WASM_OUTPUT_DIR}/hd-wallet-wasi.wasm"
        "${WASM_NPM_DIR}/hd-wallet-wasi.wasm"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/wasm/src/index.d.ts"
        "${WASM_NPM_DIR}/index.d.ts"
      COMMENT "NPM package created in ${WASM_NPM_DIR}"
    )

    # Strip node: protocol prefixes so the bundle is browser-compatible
    find_program(SED_PROGRAM sed)
    if(SED_PROGRAM)
      add_custom_command(TARGET hd_wallet_wasm_npm POST_BUILD
        COMMAND ${SED_PROGRAM} -i.bak
          -e "s/'node:module'/'module'/g"
          -e "s/'node:fs'/'fs'/g"
          -e "s/'node:path'/'path'/g"
          -e "s/'node:url'/'url'/g"
          -e "s/'node:crypto'/'crypto'/g"
          "${WASM_NPM_DIR}/hd-wallet.js"
        COMMAND ${CMAKE_COMMAND} -E remove -f "${WASM_NPM_DIR}/hd-wallet.js.bak"
        COMMENT "Stripping node: protocol prefixes from JS bundle"
      )
    endif()

    # Run wasm-opt on the standalone .wasm for non-JS runtimes
    if(WASM_OPT)
      add_custom_command(TARGET hd_wallet_wasm_npm POST_BUILD
        COMMAND "$<$<CONFIG:Release>:${WASM_OPT}>"
                $<$<CONFIG:Release>:-O3>
                $<$<CONFIG:Release>:--strip-debug>
                $<$<CONFIG:Release>:--strip-producers>
                $<$<CONFIG:Release>:--all-features>
                $<$<CONFIG:Release>:-o>
                $<$<CONFIG:Release>:${WASM_NPM_DIR}/hd-wallet.wasm>
                $<$<CONFIG:Release>:${WASM_NPM_DIR}/hd-wallet.wasm>
        COMMENT "Optimizing standalone WASM binary with wasm-opt -O3"
      )
    endif()

    # Stage the typed high-level runtime only after the canonical raw/WASI
    # artifacts and all post-processing are complete. Every local and hosted
    # caller of hd_wallet_wasm_npm therefore receives the same package graph.
    find_program(NODE_PROGRAM NAMES node)
    if(NOT NODE_PROGRAM)
      message(FATAL_ERROR "Node.js is required to stage the core NPM package")
    endif()
    add_custom_command(TARGET hd_wallet_wasm_npm POST_BUILD
      COMMAND "${NODE_PROGRAM}" "${CMAKE_SOURCE_DIR}/scripts/stage-core-package.mjs"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      COMMENT "Staging deterministic typed core package runtime"
    )

    message(STATUS "WASM targets configured:")
    message(STATUS "  hd_wallet_wasm        - WASI standalone module (.wasm)")
    message(STATUS "  hd_wallet_wasm_js     - JavaScript ES6 module (.js + .wasm)")
    message(STATUS "  hd_wallet_wasm_inline - Single file (inlined WASM)")
    message(STATUS "  hd_wallet_wasm_npm    - NPM package")
    message(STATUS "")
    message(STATUS "WASI Bridge Features (require host callbacks):")
    message(STATUS "  - USB/HID (hardware wallets)")
    message(STATUS "  - Network (RPC, node communication)")
    message(STATUS "  - Filesystem (key storage)")
    message(STATUS "  - Entropy source (random numbers)")
    message(STATUS "")

  else()
    # Not running with Emscripten - provide instructions
    message(STATUS "")
    message(STATUS "To build WASM, use Emscripten toolchain:")
    message(STATUS "  emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON")
    message(STATUS "  cmake --build build")
    message(STATUS "")
  endif()
endif()

# =============================================================================
# Tests (native only)
# =============================================================================

if(HD_WALLET_BUILD_TESTS AND NOT EMSCRIPTEN)
  enable_testing()

  # Copy the committed, integrity-checked test vectors into the build tree.
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/trezor-bip39-vectors.json
    ${CMAKE_BINARY_DIR}/test_data/vectors.json
    COPYONLY
  )

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/sdn-wallet-vectors.v1.json
    ${CMAKE_BINARY_DIR}/test_data/sdn-wallet-vectors.v1.json
    COPYONLY
  )

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/sdn-operation-wire-v1.json
    ${CMAKE_BINARY_DIR}/test_data/sdn-operation-wire-v1.json
    COPYONLY
  )

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/sdn-remember-wallet-v2.json
    ${CMAKE_BINARY_DIR}/test_data/sdn-remember-wallet-v2.json
    COPYONLY
  )

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/release/protocol/asset-review-v1.json
    ${CMAKE_BINARY_DIR}/test_data/asset-review-v1.json
    COPYONLY
  )

  add_executable(hd_wallet_tests
    test/test_main.cpp
    test/test_version.cpp
    test/test_bip39.cpp
    test/test_bip32.cpp
    test/test_curves.cpp
    test/test_bitcoin.cpp
    test/test_ethereum.cpp
    test/test_coin_addresses.cpp
    test/test_ecies.cpp
    test/test_x509.cpp
    test/test_vectors.cpp
  )
  target_link_libraries(hd_wallet_tests PRIVATE hd_wallet)
  target_include_directories(hd_wallet_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
  )
  target_compile_definitions(hd_wallet_tests PRIVATE
    TEST_VECTORS_PATH="${CMAKE_BINARY_DIR}/test_data"
  )

  add_test(NAME hd_wallet_tests COMMAND hd_wallet_tests)

  add_executable(test_password_profile
    test/test_main.cpp
    test/test_password_profile.cpp
  )
  target_link_libraries(test_password_profile PRIVATE hd_wallet)
  target_include_directories(test_password_profile PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(test_password_profile PRIVATE
    HD_WALLET_PASSWORD_PROFILE_TESTING=1
  )

  add_executable(test_sdn_vectors
    test/test_main.cpp
    test/test_sdn_vectors.cpp
  )
  target_link_libraries(test_sdn_vectors PRIVATE hd_wallet)
  target_include_directories(test_sdn_vectors PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
  )
  target_compile_definitions(test_sdn_vectors PRIVATE
    TEST_VECTORS_PATH="${CMAKE_BINARY_DIR}/test_data"
  )

  add_executable(test_sdn_identity
    test/test_main.cpp
    test/test_sdn_identity.cpp
  )
  target_link_libraries(test_sdn_identity PRIVATE hd_wallet)
  target_include_directories(test_sdn_identity PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(test_sdn_identity PRIVATE
    HD_WALLET_PASSWORD_PROFILE_TESTING=1
    HD_WALLET_SDN_IDENTITY_TESTING=1
    TEST_VECTORS_PATH="${CMAKE_BINARY_DIR}/test_data"
  )

  add_executable(test_sdn_signing
    test/test_main.cpp
    test/test_sdn_signing.cpp
  )
  target_link_libraries(test_sdn_signing PRIVATE hd_wallet)
  target_include_directories(test_sdn_signing PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(test_sdn_signing PRIVATE
    HD_WALLET_SDN_IDENTITY_TESTING=1
    TEST_VECTORS_PATH="${CMAKE_BINARY_DIR}/test_data"
  )

  add_test(NAME test_password_profile COMMAND test_password_profile)
  add_test(NAME test_sdn_vectors COMMAND test_sdn_vectors)
  add_test(NAME test_sdn_identity COMMAND test_sdn_identity)
  add_test(NAME test_sdn_signing COMMAND test_sdn_signing)

  message(STATUS "Tests enabled: hd_wallet_tests")
endif()

# =============================================================================
# Documentation
# =============================================================================

find_package(Doxygen)
if(DOXYGEN_FOUND)
  add_custom_target(docs
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
  )
endif()

# =============================================================================
# Installation
# =============================================================================

if(NOT EMSCRIPTEN)
  include(GNUInstallDirs)

  # Install the library (without EXPORT since cryptopp is a fetched dependency)
  install(TARGETS hd_wallet
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  install(DIRECTORY include/hd_wallet
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Note: CMake export is disabled because cryptopp is fetched via FetchContent
  # and cannot be included in the export set. Users should link to hd_wallet
  # and let CMake handle the transitive cryptopp dependency.
endif()
