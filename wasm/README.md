# hd-wallet-wasm

A comprehensive HD (Hierarchical Deterministic) wallet implementation compiled to WebAssembly. Implements BIP-32, BIP-39, and BIP-44 standards with multi-curve cryptography and multi-chain support.

## Features

- **BIP-32/39/44/49/84** - Complete HD wallet derivation standards
- **Multi-curve support** - secp256k1, Ed25519, P-256, P-384, X25519
- **X.509 PKI** - P-256/P-384 certificate issuance, PEM/DER/PKCS#12 interop, wallet attestations
- **Multi-chain** - Bitcoin, Ethereum, Solana, Cosmos, Polkadot
- **AES-256-GCM** - Authenticated encryption via WASM (Crypto++/OpenSSL)
- **Hardware wallet ready** - Trezor, Ledger, KeepKey abstraction layer
- **Secure** - Crypto++ backend, secure memory handling
- **Fast** - WebAssembly performance, synchronous cryptographic operations
- **TypeScript** - Full type definitions included

## Installation

```bash
npm install hd-wallet-wasm
```

## Quick Start

```javascript
import init from 'hd-wallet-wasm';

// Initialize the WASM module
const wallet = await init();

// Inject entropy (required in WASI environments)
const entropy = crypto.getRandomValues(new Uint8Array(32));
wallet.injectEntropy(entropy);

// Generate a 24-word mnemonic
const mnemonic = wallet.mnemonic.generate(24);
console.log('Mnemonic:', mnemonic);

// Derive seed from mnemonic
const seed = wallet.mnemonic.toSeed(mnemonic, 'optional passphrase');

// Create master key
const master = wallet.hdkey.fromSeed(seed);

// Derive Bitcoin key (BIP-44: m/44'/0'/0'/0/0)
const btcKey = master.derivePath("m/44'/0'/0'/0/0");
console.log('Bitcoin public key:', wallet.utils.encodeHex(btcKey.publicKey()));

// Get Bitcoin address
const btcAddress = wallet.bitcoin.getAddress(btcKey.publicKey(), 0); // P2PKH
console.log('Bitcoin address:', btcAddress);

// Derive Ethereum key (BIP-44: m/44'/60'/0'/0/0)
const ethKey = master.derivePath("m/44'/60'/0'/0/0");
const ethAddress = wallet.ethereum.getAddress(ethKey.publicKey());
console.log('Ethereum address:', ethAddress);

// Sign a message
const signature = wallet.curves.secp256k1.sign(
  wallet.utils.sha256(new TextEncoder().encode('Hello, World!')),
  ethKey.privateKey()
);

// Clean up
btcKey.wipe();
ethKey.wipe();
master.wipe();
```

## X.509 PKI

The package includes a native `wallet.x509` API for regular Web PKI workflows.
That means you can generate interoperable X.509 certificates for TLS or device
identity, then optionally bind those certificates to an HD-wallet-backed key.

Why this exists:

- X.509 is what browsers, load balancers, mTLS stacks, and enterprise PKI tools already use
- wallet ecosystems use different key types and trust models
- `hd-wallet-wasm` bridges the two by embedding a wallet attestation inside a standard certificate

What it supports:

- P-256 and P-384 certificate keys
- self-signed and issuer-signed certificate issuance
- PEM, DER, and PKCS#12 import/export
- certificate parsing and wallet-attestation verification

Wallet attestation is additive. Certificate validation still happens through the
normal X.509 chain. The attestation adds a second proof path showing that the
certificate was bound by a selected wallet key.

```javascript
import init, { Curve, X509Encoding } from 'hd-wallet-wasm';

const wallet = await init();
const now = Math.floor(Date.now() / 1000);

const certKey = wallet.x509.generatePrivateKey(Curve.P256);
const certPem = wallet.x509.createSelfSignedCertificate(
  {
    subjectDn: 'CN=wallet.example.com,O=Digital Arsenal,C=US',
    serialHex: '1001',
    notBeforeUnix: now - 300,
    notAfterUnix: now + 31536000,
    dnsNames: ['wallet.example.com'],
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extendedKeyUsage: ['serverAuth'],
    walletAttestation: {
      curve: Curve.SECP256K1,
      privateKey: wallet.utils.decodeHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      ),
      keyLabel: 'btc-root'
    }
  },
  Curve.P256,
  certKey,
  X509Encoding.PEM
);

const parsed = wallet.x509.parseCertificate(certPem);
const valid = wallet.x509.verifyWalletAttestation(certPem);
const pkcs12 = wallet.x509.exportPkcs12(
  certPem,
  X509Encoding.PEM,
  Curve.P256,
  certKey,
  'changeit',
  'wallet-example'
);
```

Certificate keys use interoperable NIST curves. Wallet attestations can be
signed with secp256k1, Ed25519, P-256, or P-384 keys depending on the wallet
identity you want to bind.

## API Overview

### Mnemonic (BIP-39)

```javascript
// Generate mnemonic (12, 15, 18, 21, or 24 words)
const mnemonic = wallet.mnemonic.generate(24);

// Validate mnemonic
const isValid = wallet.mnemonic.validate(mnemonic);

// Convert to seed
const seed = wallet.mnemonic.toSeed(mnemonic, 'passphrase');

// Convert to/from entropy
const entropy = wallet.mnemonic.toEntropy(mnemonic);
const recovered = wallet.mnemonic.fromEntropy(entropy);

// Multiple languages supported
import { Language } from 'hd-wallet-wasm';
const japanese = wallet.mnemonic.generate(24, Language.JAPANESE);
```

### HD Keys (BIP-32)

```javascript
// From seed
const master = wallet.hdkey.fromSeed(seed);

// From extended key
const restored = wallet.hdkey.fromXprv('xprv...');
const watchOnly = wallet.hdkey.fromXpub('xpub...');

// Derivation
const child = master.deriveChild(0);
const hardened = master.deriveHardened(0);
const path = master.derivePath("m/44'/0'/0'/0/0");

// Serialization
const xprv = master.toXprv();
const xpub = master.toXpub();

// Get neutered (public only) version
const pubOnly = master.neutered();
```

### Signing & Encryption Keys (BIP-44)

The library provides dedicated helpers for deriving separate signing and encryption
keypairs from a single HD root. Signing keys use BIP-44 change=0 (external chain);
encryption keys use change=1 (internal chain).

```javascript
import { getSigningKey, getEncryptionKey, buildSigningPath, buildEncryptionPath, WellKnownCoinType } from 'hd-wallet-wasm';

const master = wallet.hdkey.fromSeed(seed);

// Get signing keypair for Ethereum (m/44'/60'/0'/0/0)
const signing = getSigningKey(master, 60);
console.log('Signing pubkey:', wallet.utils.encodeHex(signing.publicKey));
console.log('Path:', signing.path); // "m/44'/60'/0'/0/0"

// Get encryption keypair for SDN (m/44'/0'/0'/1/0)
const encryption = getEncryptionKey(master, WellKnownCoinType.SDN);
console.log('Encryption pubkey:', wallet.utils.encodeHex(encryption.publicKey));

// Use encryption key for ECDH key agreement
const shared = wallet.curves.secp256k1.ecdh(encryption.privateKey, otherPublicKey);

// Multiple keys per account (e.g., one per plugin)
const plugin0Key = getEncryptionKey(master, 0, '0', '0');
const plugin1Key = getEncryptionKey(master, 0, '0', '1');

// Path helpers are also available directly
const sigPath = buildSigningPath(60);        // "m/44'/60'/0'/0/0"
const encPath = buildEncryptionPath(0);      // "m/44'/0'/0'/1/0"

// Clean up
wallet.utils.secureWipe(signing.privateKey);
wallet.utils.secureWipe(encryption.privateKey);
master.wipe();
```

Also available as instance methods on the wallet module:

```javascript
const signing = wallet.getSigningKey(master, 60);
const encryption = wallet.getEncryptionKey(master, 0);
```

### Multi-Curve Cryptography

```javascript
import { Curve } from 'hd-wallet-wasm';

// secp256k1 (Bitcoin, Ethereum)
const sig = wallet.curves.secp256k1.sign(message, privateKey);
const valid = wallet.curves.secp256k1.verify(message, sig, publicKey);
const shared = wallet.curves.secp256k1.ecdh(myPrivate, theirPublic);

// Ed25519 (Solana)
const edSig = wallet.curves.ed25519.sign(message, privateKey);
const edValid = wallet.curves.ed25519.verify(message, edSig, publicKey);

// P-256, P-384 (FIPS compliant)
const p256Sig = wallet.curves.p256.sign(message, privateKey);
const p384Sig = wallet.curves.p384.sign(message, privateKey);

// X25519 (key exchange only)
const x25519Shared = wallet.curves.x25519.ecdh(myPrivate, theirPublic);
```

### Bitcoin

```javascript
import { BitcoinAddressType, Network } from 'hd-wallet-wasm';

// Address generation
const p2pkh = wallet.bitcoin.getAddress(pubKey, BitcoinAddressType.P2PKH);
const p2wpkh = wallet.bitcoin.getAddress(pubKey, BitcoinAddressType.P2WPKH);
const p2tr = wallet.bitcoin.getAddress(pubKey, BitcoinAddressType.P2TR);

// Testnet
const testAddr = wallet.bitcoin.getAddress(pubKey, BitcoinAddressType.P2WPKH, Network.TESTNET);

// Message signing (Bitcoin Signed Message format)
const sig = wallet.bitcoin.signMessage('Hello', privateKey);
const valid = wallet.bitcoin.verifyMessage('Hello', sig, address);
```

### Ethereum

```javascript
// Address (EIP-55 checksummed)
const address = wallet.ethereum.getAddress(publicKey);

// Message signing (EIP-191)
const sig = wallet.ethereum.signMessage('Hello', privateKey);

// Typed data signing (EIP-712)
const typedSig = wallet.ethereum.signTypedData(typedData, privateKey);

// Verify and recover signer
const signer = wallet.ethereum.verifyMessage('Hello', sig);
```

### Solana

```javascript
// Address (Base58)
const address = wallet.solana.getAddress(publicKey);

// Message signing
const sig = wallet.solana.signMessage(message, privateKey);
const valid = wallet.solana.verifyMessage(message, sig, publicKey);
```

### Cosmos

```javascript
// Address with custom prefix
const cosmosAddr = wallet.cosmos.getAddress(publicKey, 'cosmos');
const osmoAddr = wallet.cosmos.getAddress(publicKey, 'osmo');

// Amino signing (legacy)
const aminoSig = wallet.cosmos.signAmino(aminoDoc, privateKey);

// Direct signing (protobuf)
const directSig = wallet.cosmos.signDirect(bodyBytes, authInfoBytes, chainId, accountNumber, privateKey);
```

### Polkadot

```javascript
// SS58 address
const dotAddr = wallet.polkadot.getAddress(publicKey, 0);   // Polkadot
const ksmAddr = wallet.polkadot.getAddress(publicKey, 2);   // Kusama

// Message signing
const sig = wallet.polkadot.signMessage(message, privateKey);
```

### Utilities

```javascript
// Hashing
const sha256 = wallet.utils.sha256(data);
const keccak = wallet.utils.keccak256(data);
const blake2b = wallet.utils.blake2b(data, 32);

// Encoding
const hex = wallet.utils.encodeHex(data);
const base58 = wallet.utils.encodeBase58(data);
const bech32 = wallet.utils.encodeBech32('bc', data);

// Key derivation
const derived = wallet.utils.hkdf(ikm, salt, info, 32);
const pbkdf2 = wallet.utils.pbkdf2(password, salt, 100000, 32);

// Secure wipe
wallet.utils.secureWipe(sensitiveData);
```

### AES-GCM Encryption

```javascript
// Generate key and IV
const key = wallet.utils.generateAesKey(256); // 32 bytes for AES-256
const iv = wallet.utils.generateIv(); // 12 bytes

// Encrypt
const plaintext = new TextEncoder().encode('Secret data');
const { ciphertext, tag } = wallet.utils.aesGcm.encrypt(key, plaintext, iv);

// Decrypt
const decrypted = wallet.utils.aesGcm.decrypt(key, ciphertext, tag, iv);

// With additional authenticated data (AAD)
const aad = new TextEncoder().encode('context');
const enc = wallet.utils.aesGcm.encrypt(key, plaintext, iv, aad);
const dec = wallet.utils.aesGcm.decrypt(key, enc.ciphertext, enc.tag, iv, aad);
```

### Random Number Generation

```javascript
// Generate cryptographically secure random bytes
const randomBytes = wallet.utils.getRandomBytes(32);

// Generate random IV for AES-GCM (12 bytes)
const iv = wallet.utils.generateIv();

// Generate random AES key (128, 192, or 256 bits)
const aes128Key = wallet.utils.generateAesKey(128);
const aes256Key = wallet.utils.generateAesKey(256);
```

## Coin Types (SLIP-44)

```javascript
import { CoinType } from 'hd-wallet-wasm';

CoinType.BITCOIN         // 0
CoinType.BITCOIN_TESTNET // 1
CoinType.LITECOIN        // 2
CoinType.ETHEREUM        // 60
CoinType.COSMOS          // 118
CoinType.POLKADOT        // 354
CoinType.SOLANA          // 501
// ... and 50+ more
```

## Browser Usage

```html
<script type="module">
import init from 'https://unpkg.com/hd-wallet-wasm/src/index.mjs';

const wallet = await init();
// Use wallet...
</script>
```

## Security Notes

- Always inject entropy from a cryptographically secure source before generating mnemonics
- Use `wipe()` to securely clear sensitive key material when done
- Never log or expose private keys or mnemonics
- Consider using hardware wallets for high-value operations
- The library enforces key separation: external chain (0) for signing, internal chain (1) for encryption

## FIPS 140-3 Mode

The published NPM package includes OpenSSL 3.0.9 FIPS Provider support for compliance-critical applications.

### Enabling FIPS Mode

```javascript
import init from 'hd-wallet-wasm';

const wallet = await init();

// Check if OpenSSL is available
console.log('OpenSSL compiled:', wallet.isOpenSSL());

// Initialize FIPS mode
const fipsEnabled = wallet.initFips();
console.log('FIPS active:', wallet.isOpenSSLFips());
```

### Algorithm Routing

When FIPS mode is active, approved algorithms use OpenSSL FIPS provider:

| Algorithm | FIPS Mode | Default |
|-----------|-----------|---------|
| SHA-256/384/512 | OpenSSL FIPS | Crypto++ |
| AES-256-GCM | OpenSSL FIPS | Crypto++ |
| ECDSA P-256/P-384 | OpenSSL FIPS | Crypto++ |
| HKDF/PBKDF2 | OpenSSL FIPS | Crypto++ |
| secp256k1 | Crypto++ | Crypto++ |
| Ed25519 | Crypto++ | Crypto++ |
| Keccak-256 | Crypto++ | Crypto++ |

**Note:** secp256k1 (Bitcoin/Ethereum) and Ed25519 (Solana) are not FIPS-approved and always use Crypto++.

### API Reference

| Method | Description |
|--------|-------------|
| `wallet.isOpenSSL()` | Check if OpenSSL backend is compiled in |
| `wallet.initFips()` | Initialize FIPS mode; returns true if successful |
| `wallet.isOpenSSLFips()` | Check if FIPS provider is currently active |
| `wallet.isFipsMode()` | Check if compiled with FIPS mode enabled |

See the [main README](https://github.com/DigitalArsenal/hd-wallet-wasm#fips-140-3-compliance) for comprehensive FIPS documentation.

## License

Apache-2.0

## Links

- [Documentation](https://digitalarsenal.github.io/hd-wallet-wasm/)
- [GitHub](https://github.com/DigitalArsenal/hd-wallet-wasm)
- [API Reference](https://digitalarsenal.github.io/hd-wallet-wasm/api/)
