# HD Wallet WASM

[![Build and Test](https://github.com/DigitalArsenal/hd-wallet-wasm/actions/workflows/build.yml/badge.svg)](https://github.com/DigitalArsenal/hd-wallet-wasm/actions/workflows/build.yml)
[![npm version](https://img.shields.io/npm/v/hd-wallet-wasm.svg)](https://www.npmjs.com/package/hd-wallet-wasm)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive hierarchical deterministic (HD) wallet implementation in pure C++ with Crypto++, compiled to WebAssembly for cross-platform compatibility.

## Overview

HD Wallet WASM provides a complete implementation of BIP-32/39/44 hierarchical deterministic wallets with extensive multi-chain and multi-curve support. The library is written in pure C++ using the Crypto++ cryptographic library and compiles to WebAssembly, enabling use in browsers, Node.js, and any WASI-compatible runtime (Go, Rust, Python, etc.).

**Key capabilities:**

- **BIP Standards**: Full implementation of BIP-32 (HD derivation), BIP-39 (mnemonics), and BIP-44/49/84 (derivation paths)
- **Multi-Curve Cryptography**: secp256k1, Ed25519, NIST P-256, NIST P-384, and X25519
- **X.509 PKI**: P-256/P-384 certificate issuance, PEM/DER/PKCS#12 interop, and wallet-backed certificate attestations
- **Multi-Chain Support**: Bitcoin, Ethereum, Cosmos, Solana, Polkadot, and 50+ coins via SLIP-44
- **Hardware Wallet Abstraction**: Unified API for KeepKey, Trezor, and Ledger devices
- **WebAssembly**: Pure C++ compiled to WASM for cross-language interoperability

## Features

- **Mnemonic Generation & Validation**
  - 12, 15, 18, 21, or 24 word phrases
  - English wordlist support (other BIP-39 locales are not compiled in this build)
  - Word suggestion and autocomplete

- **HD Key Derivation**
  - BIP-32 hierarchical deterministic keys
  - Hardened and non-hardened derivation
  - Extended public/private key serialization (xprv/xpub)

- **Multi-Curve Support**
  - secp256k1 (Bitcoin, Ethereum, Cosmos)
  - Ed25519 (Solana, Polkadot)
  - NIST P-256 (secp256r1)
  - NIST P-384 (secp384r1)
  - X25519 (key exchange)

- **Blockchain Support**
  - Bitcoin: P2PKH, P2SH, P2WPKH, P2WSH, Taproot addresses; transaction building and signing
  - Ethereum: EIP-55 checksum addresses, EIP-191 message signing, EIP-712 typed data, legacy and EIP-1559 transactions
  - Cosmos/Tendermint: Amino and Direct signing
  - Solana: Ed25519 addresses and signing
  - Polkadot: SS58 addresses, Sr25519/Ed25519 signing

- **Hardware Wallet Support**
  - Unified abstraction for KeepKey, Trezor, and Ledger
  - Device enumeration, connection management
  - Transaction and message signing via device

- **X.509 PKI**
  - Generate P-256 and P-384 certificate private keys
  - Create self-signed certificates or issue subordinate certificates
  - Import/export PEM, DER, and PKCS#12 bundles
  - Embed and verify wallet attestations that bind a certificate to a selected wallet key

- **Security**
  - Secure memory wiping with volatile pointers and memory barriers
  - SecureVector/SecureArray with secure allocator (wipes on reallocation)
  - MaskedKey XOR-masking for private keys at rest
  - Constant-time signature verification (DER encoding)
  - Thread-safe callback registration
  - Memory locking to prevent swapping (mlock)
  - Optional FIPS-compliant mode

- **Cryptographic Utilities**
  - Hash functions: SHA-256, SHA-512, Keccak-256, RIPEMD-160, BLAKE2b/s
  - Key derivation: HKDF, PBKDF2, scrypt
  - Encryption: AES-256-GCM (authenticated), AES-128/192/256-CTR (streaming)
  - ECIES: Unified encrypt/decrypt (ECDH + HKDF-SHA256 + AES-256-GCM)
  - Encoding: Base58, Base58Check, Bech32, Hex, Base64
  - Random: Secure random bytes, IV generation, AES key generation

## Installation

### NPM

```bash
npm install hd-wallet-wasm
```

### CDN

```html
<!-- ES Module -->
<script type="module">
  import HDWalletWasm from 'https://unpkg.com/hd-wallet-wasm/dist/hd-wallet.js';

  const wallet = await HDWalletWasm();
  // Use wallet...
</script>
```

### Building from Source

**Prerequisites:**
- CMake 3.16+
- C++17 compiler (GCC 8+, Clang 10+, MSVC 2019+)
- Emscripten SDK (for WASM builds)

```bash
# Clone the repository
git clone https://github.com/DigitalArsenal/hd-wallet-wasm.git
cd hd-wallet-wasm

# Native build
cmake -B build -S .
cmake --build build

# WASM build (requires Emscripten)
emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON
cmake --build build
```

## Quick Start

### Generating a Mnemonic

```javascript
import HDWalletWasm, { Curve, BitcoinAddressType, Network, WasiFeature } from 'hd-wallet-wasm';

const wallet = await HDWalletWasm();

// Generate a 24-word mnemonic
const mnemonic = wallet.mnemonic.generate(24);
console.log('Mnemonic:', mnemonic);

// Validate mnemonic
const isValid = wallet.mnemonic.validate(mnemonic);
console.log('Valid:', isValid);

// Convert to seed (with optional passphrase)
const seed = wallet.mnemonic.toSeed(mnemonic, 'optional passphrase');
```

### Deriving Keys

```javascript
// Create master key from seed
const masterKey = wallet.hdkey.fromSeed(seed);

// Derive using BIP-44 path for Ethereum
// m/44'/60'/0'/0/0
const ethKey = masterKey.derivePath("m/44'/60'/0'/0/0");

// Get private and public keys
const privateKey = ethKey.privateKey();
const publicKey = ethKey.publicKey();

// Serialize as extended keys
const xprv = masterKey.toXprv();
const xpub = masterKey.toXpub();

// Wipe sensitive data when done
ethKey.wipe();
masterKey.wipe();
```

### Getting Addresses

```javascript
// Bitcoin addresses (various formats)
const btcKey = masterKey.derivePath("m/84'/0'/0'/0/0");
const p2wpkh = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2WPKH);
const p2pkh = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2PKH);
const taproot = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2TR);

// Ethereum address
const ethKey = masterKey.derivePath("m/44'/60'/0'/0/0");
const ethAddress = wallet.ethereum.getAddress(ethKey.publicKey());
const checksumAddress = wallet.ethereum.getChecksumAddress(ethAddress);

// Solana address (Ed25519)
const solSeed = wallet.mnemonic.toSeed(mnemonic);
const solKey = wallet.hdkey.fromSeed(solSeed, Curve.ED25519);
const solAddress = wallet.solana.getAddress(solKey.derivePath("m/44'/501'/0'/0'").publicKey());

// Cosmos address
const cosmosKey = masterKey.derivePath("m/44'/118'/0'/0/0");
const cosmosAddress = wallet.cosmos.getAddress(cosmosKey.publicKey(), 'cosmos');
```

### Signing Messages

```javascript
// Bitcoin signed message
const btcSignature = wallet.bitcoin.signMessage('Hello Bitcoin!', btcKey.privateKey());

// Ethereum signed message (EIP-191)
const ethSignature = wallet.ethereum.signMessage('Hello Ethereum!', ethKey.privateKey());

// Ethereum typed data (EIP-712)
const typedData = {
  types: { /* ... */ },
  primaryType: 'Mail',
  domain: { /* ... */ },
  message: { /* ... */ }
};
const typedSignature = wallet.ethereum.signTypedData(typedData, ethKey.privateKey());

// Raw curve signing
const messageHash = wallet.utils.keccak256(new TextEncoder().encode('message'));
const { signature, recoveryId } = wallet.curves.secp256k1.signRecoverable(messageHash, privateKey);
const recovered = wallet.curves.secp256k1.recover(messageHash, signature, recoveryId);
```

### AES-GCM Encryption

```javascript
// Generate a key and IV
const aesKey = wallet.utils.generateAesKey(256); // 32 bytes
const iv = wallet.utils.generateIv(); // 12 bytes

// Encrypt data
const plaintext = new TextEncoder().encode('Secret message');
const { ciphertext, tag } = wallet.utils.aesGcm.encrypt(aesKey, plaintext, iv);

// Decrypt data
const decrypted = wallet.utils.aesGcm.decrypt(aesKey, ciphertext, tag, iv);
console.log(new TextDecoder().decode(decrypted)); // 'Secret message'

// With additional authenticated data (AAD)
const aad = new TextEncoder().encode('associated data');
const encrypted = wallet.utils.aesGcm.encrypt(aesKey, plaintext, iv, aad);
const decryptedWithAad = wallet.utils.aesGcm.decrypt(aesKey, encrypted.ciphertext, encrypted.tag, iv, aad);
```

### ECIES (Elliptic Curve Integrated Encryption)

ECIES combines ECDH key agreement, HKDF-SHA256 key derivation, and AES-256-GCM
into a single encrypt/decrypt API. Supports secp256k1, P-256, P-384, and X25519.

```javascript
// Encrypt for a recipient using their public key
const encrypted = wallet.ecies.encrypt('x25519', recipientPublicKey, plaintext);

// Decrypt with the recipient's private key
const decrypted = wallet.ecies.decrypt('x25519', recipientPrivateKey, encrypted);

// With additional authenticated data (AAD)
const encrypted = wallet.ecies.encrypt('secp256k1', recipientPubKey, plaintext, aad);
const decrypted = wallet.ecies.decrypt('secp256k1', recipientPrivKey, encrypted, aad);
```

Wire format: `[ephemeral_pubkey][iv (12B)][ciphertext][tag (16B)]`

| Curve     | Overhead |
|-----------|----------|
| secp256k1 | 61 bytes |
| P-256     | 61 bytes |
| P-384     | 77 bytes |
| X25519    | 60 bytes |

### AES-CTR Encryption

Counter mode encryption for streaming use cases. No authentication — pair with HMAC for integrity.

```javascript
// AES-256-CTR
const key = wallet.utils.generateAesKey(256);
const iv = wallet.utils.generateRandomBytes(16); // 16-byte IV for CTR mode
const ciphertext = wallet.aesCtr.encrypt(key, plaintext, iv);
const decrypted = wallet.aesCtr.decrypt(key, ciphertext, iv);

// Also supports AES-128-CTR and AES-192-CTR (key size selects variant)
```

### Building Transactions

```javascript
// Bitcoin transaction
const btcTx = wallet.bitcoin.tx.create()
  .addInput('txid...', 0)
  .addOutput('bc1q...', 50000n)
  .sign(0, btcKey.privateKey());

const btcRawTx = btcTx.serialize();
const txid = btcTx.getTxid();

// Ethereum transaction (EIP-1559)
const ethTx = wallet.ethereum.tx.createEIP1559({
  nonce: 0,
  maxFeePerGas: 30000000000n,
  maxPriorityFeePerGas: 1000000000n,
  gasLimit: 21000n,
  to: '0x...',
  value: 1000000000000000000n,
  chainId: 1
}).sign(ethKey.privateKey());

const ethRawTx = ethTx.serialize();
```

### X.509 PKI and Wallet Attestations

`hd-wallet-wasm` now ships a native X.509 stack because regular Web PKI is still
the format that TLS terminators, reverse proxies, browsers, mTLS deployments,
MDM systems, and enterprise certificate tooling already understand. The goal is
not to replace TLS certificates with blockchain keys. The goal is to let one
certificate carry both:

- a normal interoperable X.509 identity for existing TLS and PKI infrastructure
- an optional wallet attestation proving the certificate was bound by a selected
  wallet key

Certificate issuance uses NIST P-256 or P-384 keys for broad interoperability
and FIPS-aligned deployments. Wallet attestations can be signed by secp256k1,
Ed25519, P-256, or P-384 wallet keys. The attestation is stored in a non-critical
certificate comment extension and signs a canonical payload over the certificate
serial, issuer/subject DNs, validity window, and SPKI digest. A verifier can
perform normal certificate-chain validation first, then independently verify the
embedded wallet proof.

Supported `wallet.x509` operations:

- generate certificate private keys
- create self-signed or issuer-signed certificates
- convert certificates between PEM and DER
- parse certificate metadata
- export/import PKCS#12 bundles
- verify embedded wallet attestations

```javascript
import HDWalletWasm, { Curve, X509Encoding } from 'hd-wallet-wasm';

const wallet = await HDWalletWasm();
const now = Math.floor(Date.now() / 1000);

const certificateKey = wallet.x509.generatePrivateKey(Curve.P256);
const walletKey = wallet.hdkey
  .fromSeed(wallet.mnemonic.toSeed(wallet.mnemonic.generate(24)))
  .derivePath("m/44'/0'/0'/0/0");

const certificatePem = wallet.x509.createSelfSignedCertificate(
  {
    subjectDn: 'CN=api.example.com,O=Digital Arsenal,C=US',
    serialHex: '1001',
    notBeforeUnix: now - 300,
    notAfterUnix: now + 31536000,
    dnsNames: ['api.example.com'],
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extendedKeyUsage: ['serverAuth'],
    walletAttestation: {
      curve: Curve.SECP256K1,
      privateKey: walletKey.privateKey(),
      keyLabel: 'btc-root'
    }
  },
  Curve.P256,
  certificateKey,
  X509Encoding.PEM
);

const parsed = wallet.x509.parseCertificate(certificatePem);
const walletProofValid = wallet.x509.verifyWalletAttestation(certificatePem);
const pkcs12 = wallet.x509.exportPkcs12(
  certificatePem,
  X509Encoding.PEM,
  Curve.P256,
  certificateKey,
  'changeit',
  'api-example'
);
```

This gives you a standard certificate that existing TLS tooling can consume,
plus a second proof path that can say "this server certificate was attested by
this wallet key". That is the bridge between Web PKI and HD-wallet identity.

## API Reference

Full API documentation is available at [https://digitalarsenal.github.io/hd-wallet-wasm/](https://digitalarsenal.github.io/hd-wallet-wasm/).

### Main APIs

| API | Description |
|-----|-------------|
| `mnemonic` | BIP-39 mnemonic generation, validation, and conversion |
| `hdkey` | BIP-32 HD key derivation and serialization |
| `curves` | Multi-curve cryptography (secp256k1, Ed25519, P-256, P-384, X25519) |
| `bitcoin` | Bitcoin addresses, message signing, transaction building |
| `ethereum` | Ethereum addresses, EIP-191/712 signing, transactions |
| `cosmos` | Cosmos/Tendermint addresses and signing |
| `solana` | Solana addresses and signing |
| `polkadot` | Polkadot/Substrate addresses and signing |
| `hardware` | Hardware wallet abstraction (KeepKey, Trezor, Ledger) |
| `keyring` | Multi-wallet key management |
| `x509` | X.509 certificate issuance, import/export, parsing, and wallet attestation verification |
| `ecies` | ECIES encrypt/decrypt (ECDH + HKDF + AES-GCM), AES-CTR |
| `utils` | Hash functions, encoding, key derivation, AES-GCM encryption |

### Low-Level C API

The library exports 200+ C functions for direct WASM interop:

```javascript
// Direct ccall usage
const mnemonic = wallet.ccall('hd_mnemonic_generate', 'string', ['number'], [24]);
const isValid = wallet.ccall('hd_mnemonic_validate', 'number', ['string'], [mnemonic]);
```

## Building

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `HD_WALLET_BUILD_WASM` | OFF | Build WebAssembly targets |
| `HD_WALLET_BUILD_TESTS` | ON | Build test suite |
| `HD_WALLET_USE_CRYPTOPP` | ON | Use Crypto++ backend |
| `HD_WALLET_USE_OPENSSL` | ON | Use OpenSSL for FIPS-approved algorithms |
| `HD_WALLET_FIPS_MODE` | OFF | Enable FIPS-compliant mode |
| `HD_WALLET_ENABLE_BITCOIN` | ON | Enable Bitcoin support |
| `HD_WALLET_ENABLE_ETHEREUM` | ON | Enable Ethereum support |
| `HD_WALLET_ENABLE_COSMOS` | ON | Enable Cosmos support |
| `HD_WALLET_ENABLE_SOLANA` | ON | Enable Solana support |
| `HD_WALLET_ENABLE_POLKADOT` | ON | Enable Polkadot support |

### Build Targets

| Target | Description | Output |
|--------|-------------|--------|
| `hd_wallet_wasm` | WASI standalone module | `.wasm` |
| `hd_wallet_wasm_js` | JavaScript ES6 module | `.js` + `.wasm` |
| `hd_wallet_wasm_inline` | Single-file (inlined WASM) | `.js` |
| `hd_wallet_wasm_npm` | NPM package | `wasm/dist/` |

### Native Build

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# Run tests
ctest --test-dir build --output-on-failure
```

### WASM Build

```bash
# Install Emscripten locally (first time only)
cd packages
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
cd ../..

# Activate Emscripten (each session)
source packages/emsdk/emsdk_env.sh

# Configure and build
emcmake cmake -B build-wasm -S . -DHD_WALLET_BUILD_WASM=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm --parallel

# Output in build-wasm/wasm/ and wasm/dist/
```

## FIPS 140-3 Compliance

HD Wallet WASM supports FIPS 140-3 compliance through an optional OpenSSL 3.0.9 backend with the FIPS Provider. This is essential for applications requiring government-grade cryptographic compliance (financial institutions, healthcare, defense contractors, etc.).

### Overview

The library provides two cryptographic backends:

| Backend | Use Case | Certification |
|---------|----------|---------------|
| **Crypto++** (default) | General purpose, all curves | Not FIPS certified |
| **OpenSSL FIPS** | Compliance-critical operations | FIPS 140-3 Certificate #4282 |

When OpenSSL is enabled, FIPS-approved algorithms automatically route through OpenSSL while non-approved algorithms (secp256k1, Ed25519, Keccak) continue using Crypto++.

### Algorithm Routing

| Algorithm | OpenSSL FIPS Mode | Default (Crypto++) |
|-----------|-------------------|-------------------|
| **Hash Functions** | | |
| SHA-256/384/512 | ✅ OpenSSL FIPS | Crypto++ |
| SHA3-256/384/512 | ✅ OpenSSL FIPS | Crypto++ |
| HMAC-SHA256/512 | ✅ OpenSSL FIPS | Crypto++ |
| Keccak-256 | ❌ Crypto++ | Crypto++ |
| RIPEMD-160 | ❌ Crypto++ | Crypto++ |
| BLAKE2b/s | ❌ Crypto++ | Crypto++ |
| **Key Derivation** | | |
| HKDF-SHA256/384/512 | ✅ OpenSSL FIPS | Crypto++ |
| PBKDF2-SHA256/512 | ✅ OpenSSL FIPS | Crypto++ |
| scrypt | ❌ Crypto++ | Crypto++ |
| **Symmetric Encryption** | | |
| AES-128/192/256-GCM | ✅ OpenSSL FIPS | Crypto++ |
| AES-128/192/256-CTR | ✅ OpenSSL FIPS | Crypto++ |
| ECIES (ECDH+HKDF+AES-GCM) | ✅ FIPS with P-256/P-384 | Crypto++ |
| ChaCha20-Poly1305 | ❌ Crypto++ | Crypto++ |
| **Elliptic Curves** | | |
| NIST P-256 (secp256r1) | ✅ OpenSSL FIPS | Crypto++ |
| NIST P-384 (secp384r1) | ✅ OpenSSL FIPS | Crypto++ |
| NIST P-521 (secp521r1) | ✅ OpenSSL FIPS | Crypto++ |
| secp256k1 | ❌ Crypto++ | Crypto++ |
| Ed25519 | ❌ Crypto++ | Crypto++ |
| X25519 | ❌ Crypto++ | Crypto++ |
| **Random Generation** | | |
| DRBG (CTR_DRBG) | ✅ OpenSSL FIPS | Crypto++ AutoSeededRNG |

**Legend:** ✅ = FIPS-approved and uses OpenSSL FIPS provider | ❌ = Not FIPS-approved, uses Crypto++

### Building with FIPS Support

#### Step 1: Build OpenSSL for WebAssembly

```bash
# First time only - builds OpenSSL 3.0.9 with FIPS provider for WASM
cd openssl-fips
./build.sh
cd ..

# This creates:
#   openssl-fips/dist/lib/libcrypto.a   - OpenSSL crypto library (WASM)
#   openssl-fips/dist/lib/fips.a        - FIPS provider module
#   openssl-fips/dist/include/          - OpenSSL headers
```

#### Step 2: Build HD Wallet with OpenSSL

```bash
emcmake cmake -B build-wasm -S . \
  -DHD_WALLET_BUILD_WASM=ON \
  -DHD_WALLET_USE_OPENSSL=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-wasm --parallel
```

#### CI/CD Build

The published NPM package includes OpenSSL FIPS support. The GitHub Actions workflow automatically:
1. Caches the OpenSSL FIPS build
2. Links against `openssl-fips/dist/lib/libcrypto.a`
3. Exports FIPS initialization functions

### Runtime API

#### Initializing FIPS Mode

```javascript
import HDWalletWasm from 'hd-wallet-wasm';

const wallet = await HDWalletWasm();

// Check if OpenSSL backend is compiled in
console.log('OpenSSL available:', wallet.isOpenSSL());

// Initialize FIPS mode
const fipsEnabled = wallet.initFips();

if (fipsEnabled) {
  console.log('✅ FIPS 140-3 mode activated');
  console.log('   Using OpenSSL FIPS provider for approved algorithms');
} else {
  console.log('⚠️ FIPS mode not available');
  console.log('   Using default Crypto++ backend');
}

// Verify FIPS status
console.log('FIPS active:', wallet.isOpenSSLFips());
```

#### API Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `wallet.isOpenSSL()` | `boolean` | Check if OpenSSL backend is compiled in |
| `wallet.initFips()` | `boolean` | Initialize FIPS mode; returns true if successful |
| `wallet.isOpenSSLFips()` | `boolean` | Check if FIPS provider is currently active |
| `wallet.isFipsMode()` | `boolean` | Check if library was compiled with FIPS mode enabled |

#### Conditional Code Paths

```javascript
const wallet = await HDWalletWasm();

// Initialize appropriate mode
if (wallet.isOpenSSL()) {
  const fips = wallet.initFips();
  if (!fips) {
    console.warn('FIPS unavailable, falling back to default OpenSSL');
  }
}

// Use FIPS-approved algorithms when compliance required
if (wallet.isOpenSSLFips()) {
  // Use P-256/P-384 for ECDSA (FIPS-approved)
  const p256Key = wallet.hdkey.fromSeed(seed, Curve.P256);
  const signature = wallet.curves.p256.sign(hash, privateKey);
} else {
  // Standard secp256k1 for Ethereum/Bitcoin
  const btcKey = wallet.hdkey.fromSeed(seed, Curve.SECP256K1);
  const signature = wallet.curves.secp256k1.sign(hash, privateKey);
}
```

### Compliance Considerations

#### What FIPS Mode Provides

- ✅ **Certified Algorithms**: SHA-2, AES-GCM, ECDSA P-256/P-384, ECDH, HKDF, PBKDF2
- ✅ **Validated Implementation**: OpenSSL 3.0.9 FIPS Provider (Certificate #4282)
- ✅ **Approved DRBG**: NIST SP 800-90A compliant random generation
- ✅ **Key Zeroization**: FIPS-compliant key destruction

#### What FIPS Mode Does NOT Cover

- ❌ **secp256k1**: Required for Bitcoin/Ethereum but not FIPS-approved
- ❌ **Ed25519**: Required for Solana but not FIPS-approved
- ❌ **Keccak-256**: Required for Ethereum addresses but not FIPS-approved
- ❌ **BLAKE2**: Not FIPS-approved (use SHA-3 instead)
- ❌ **BIP-39 PBKDF2**: Uses 2048 iterations (FIPS minimum is 1000, but higher recommended)

#### Hybrid Mode (Recommended)

For blockchain applications requiring both compliance and cryptocurrency support:

```javascript
const wallet = await HDWalletWasm();

// Enable FIPS for approved operations
wallet.initFips();

// FIPS-compliant operations (use OpenSSL FIPS)
const aesKey = wallet.utils.generateAesKey(256);        // AES-256 key via FIPS DRBG
const encrypted = wallet.utils.aesGcm.encrypt(          // AES-GCM via FIPS
  aesKey, plaintext, iv
);
const p256Sig = wallet.curves.p256.sign(hash, p256Key); // ECDSA P-256 via FIPS

// Non-FIPS operations (use Crypto++)
const ethKey = masterKey.derivePath("m/44'/60'/0'/0/0"); // secp256k1 (Crypto++)
const ethSig = wallet.curves.secp256k1.sign(hash, ethKey.privateKey());
const keccakHash = wallet.utils.keccak256(data);         // Keccak (Crypto++)
```

### Security Best Practices

1. **Always call `initFips()` at startup** if compliance is required
2. **Check `isOpenSSLFips()`** before performing compliance-critical operations
3. **Use P-256/P-384** instead of secp256k1 when FIPS compliance trumps blockchain compatibility
4. **Use SHA-256/SHA-512** instead of Keccak-256 for hashing when possible
5. **Log FIPS status** at application startup for audit trails

```javascript
// Startup audit logging
const wallet = await HDWalletWasm();
const fipsStatus = {
  openssl_compiled: wallet.isOpenSSL(),
  fips_initialized: wallet.initFips(),
  fips_active: wallet.isOpenSSLFips(),
  timestamp: new Date().toISOString()
};
console.log('Cryptographic status:', JSON.stringify(fipsStatus));
// { openssl_compiled: true, fips_initialized: true, fips_active: true, timestamp: "..." }
```

### Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `isOpenSSL()` returns `false` | Not compiled with OpenSSL | Rebuild with `-DHD_WALLET_USE_OPENSSL=ON` |
| `initFips()` returns `false` | FIPS provider not available | Ensure `openssl-fips/build.sh` ran successfully |
| FIPS operations fail | Provider initialization failed | Check console for OpenSSL error messages |
| Performance degradation | FIPS provider overhead | Expected; FIPS validation adds overhead |

## Testing

### Native Tests

```bash
# Build and run C++ tests
cmake -B build -S . -DHD_WALLET_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### JavaScript Tests

```bash
cd wasm
npm install
npm test

# Individual test suites
npm run test:bip39
npm run test:bip32
npm run test:vectors
```

### Test Vectors

The library is validated against official BIP-39/BIP-32 test vectors from the Trezor reference implementation.

## Security

### Key Separation

The library enforces key separation best practices:

- Signing keys and encryption keys are derived from separate paths
- Hardware wallet operations use isolated derivation paths
- Public keys can be derived without exposing private keys (neutered keys)

### Secure Memory

All sensitive cryptographic material uses secure memory handling:

```cpp
// C++ - SecureVector automatically wipes on destruction
SecureVector<uint8_t> privateKey = deriveKey(...);
// Memory is securely wiped when privateKey goes out of scope

// JavaScript - explicit wipe
const key = wallet.hdkey.fromSeed(seed);
// ... use key ...
key.wipe(); // Securely wipes memory
```

Key security features:

- **Secure wiping**: Uses volatile writes with compiler memory barriers (`__asm__ __volatile__`) to prevent optimization from removing memory clearing
- **Secure allocator**: `SecureAllocator<T>` wipes memory on deallocation, including during `std::vector` reallocation -- freed buffers are always wiped
- **MaskedKey**: Private keys stored XOR-masked with a random session key; only revealed temporarily via RAII `RevealedKey` that auto-wipes
- **Constant-time operations**: Signature verification uses fixed-size buffers; comparison uses XOR accumulation
- **Thread safety**: Callback registration protected by mutex; global string buffers use `thread_local` storage
- **Memory locking**: On supported platforms, sensitive memory is locked to prevent swapping to disk
- **Exception-safe WASI**: Integer parsing uses safe manual parsers instead of `std::stoull` to avoid `abort()` in no-exceptions builds

### WASM Memory Model

WebAssembly's linear memory has inherent limitations for cryptographic applications:

- **Flat address space**: All data (including private keys) exists in a single contiguous memory region accessible via the host language (e.g., `HEAPU8.buffer` in JavaScript)
- **No memory protection**: WASM lacks hardware memory protection (NX bits, guard pages, ASLR)
- **Memory cannot shrink**: `memory.grow` is one-directional; wiped data remains in the allocated region

The library mitigates these limitations through MaskedKey XOR-masking, secure wiping, and RAII cleanup patterns. However, applications handling high-value keys should consider additional isolation measures at the host level (Content Security Policy, Subresource Integrity, restricted script access).

### WASI Considerations

When running in WASI environments:

- **Entropy**: The library requires entropy injection for mnemonic generation. Use `injectEntropy()` to provide cryptographically secure random bytes
- **Hardware wallets**: Require host bridge callbacks for USB/HID communication
- **Network operations**: Require WASI sockets or host bridge

The library provides runtime warnings when features are unavailable:

```javascript
if (!wallet.wasiHasFeature(WasiFeature.RANDOM)) {
  console.warn(wallet.wasiGetWarningMessage(WasiFeature.RANDOM));
  // "Random number generation requires entropy injection in WASI environment"
}
```

### Recommendations

1. **Never log or persist mnemonics/private keys** - Use the library's secure storage mechanisms
2. **Always wipe keys when done** - Call `.wipe()` on HDKey objects
3. **Use hardware wallets for high-value operations** - The abstraction layer provides consistent security
4. **Validate addresses before sending** - Use the `validateAddress()` methods
5. **Use checksummed addresses for Ethereum** - Prevents typos

## Project Structure

```
hd-wallet-wasm/
├── CMakeLists.txt           # Build configuration
├── include/hd_wallet/       # C++ headers
│   ├── bip32.h              # HD key derivation
│   ├── bip39.h              # Mnemonic generation
│   ├── coins/               # Chain implementations
│   ├── tx/                  # Transaction builders
│   └── hw/                  # Hardware wallet abstraction
├── src/                     # Implementation files
├── test/                    # C++ test suite
├── wasm/                    # JavaScript bindings
│   ├── src/index.mjs        # High-level JS API
│   ├── src/index.d.ts       # TypeScript definitions
│   └── dist/                # NPM package output
└── docs/                    # Documentation site
```

## License

Apache-2.0

```
Copyright 2024-2025 DigitalArsenal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Related Projects

- [Crypto++](https://www.cryptopp.com/) - Cryptographic library used for all crypto operations
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - HD wallet specification
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic specification
- [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) - Coin type registry
