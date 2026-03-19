# X.509 PKI in hd-wallet-wasm

This document describes the X.509 implementation that ships in `hd-wallet-wasm`
`2.0.1`. It replaces the earlier browser-only PKI design notes that assumed
JavaScript certificate modules which are no longer the architecture of record.

## Overview

`hd-wallet-wasm` now provides a native X.509 stack in C++ with OpenSSL-backed
certificate issuance, parsing, encoding conversion, and PKCS#12 import/export.
The WASM wrapper exposes this through `wallet.x509`.

The design goal is straightforward:

- keep standard Web PKI interoperability for TLS, mTLS, device identity, and enterprise tooling
- preserve wallet-native identity by letting a certificate carry a wallet-backed proof
- avoid inventing a repo-local certificate format that no existing TLS stack understands

In other words, this repo does not try to replace X.509. It uses X.509 as the
interoperable carrier, then adds a second proof path that binds the certificate
to a selected wallet key.

## Why We Are Using X.509

We are using X.509 because it is still the deployment format for:

- HTTPS and reverse proxies
- mutual TLS
- enterprise certificate authorities
- device and workload identity
- PKCS#12 import/export across operating systems, browsers, and keystores

If the project wants a server certificate, a client certificate, or an identity
credential that external infrastructure can consume, regular X.509 is the
portable answer.

Blockchain keys solve a different problem. They prove control of a wallet key on
their native curve and network. They do not automatically give you a TLS
certificate chain or PKCS#12 bundle that a load balancer or browser already
understands.

`hd-wallet-wasm` therefore uses both:

- X.509 for existing PKI and TLS interoperability
- wallet signatures to prove an additional cross-domain identity binding

## What the Repo Implements

Native C++ API:

- generate P-256 and P-384 certificate private keys
- create self-signed certificates
- issue subordinate certificates from an issuer certificate/private key
- convert certificates between PEM and DER
- parse certificate metadata to JSON
- export and import PKCS#12 bundles
- verify wallet attestations embedded in the certificate

WASM / JavaScript API:

- `wallet.x509.generatePrivateKey()`
- `wallet.x509.exportPrivateKeyPem()`
- `wallet.x509.importPrivateKeyPem()`
- `wallet.x509.createSelfSignedCertificate()`
- `wallet.x509.issueCertificate()`
- `wallet.x509.convertCertificate()`
- `wallet.x509.parseCertificate()`
- `wallet.x509.verifyWalletAttestation()`
- `wallet.x509.exportPkcs12()`
- `wallet.x509.importPkcs12()`

## Supported Algorithms and Formats

Certificate keys and signatures:

- P-256 certificates with SHA-256
- P-384 certificates with SHA-384

Wallet attestation signature curves:

- secp256k1
- Ed25519
- P-256
- P-384

Encodings and containers:

- PEM
- DER
- PKCS#12

This split is intentional. Certificate issuance stays on the broadly deployed
NIST curves that fit standard Web PKI and FIPS-oriented environments. Wallet
attestation remains flexible enough to bind the certificate to the key type that
actually backs the wallet identity.

## How Wallet Attestation Works

The wallet attestation is an additive proof embedded in a non-critical
certificate comment extension.

The attestation signs a canonical payload over:

- certificate serial number
- issuer distinguished name
- subject distinguished name
- validity window
- certificate SPKI digest

That signature is produced by a selected wallet key, such as a Bitcoin
`secp256k1` key or another supported wallet signing key.

The result is a statement of the form:

> this X.509 certificate was attested by control of this wallet key

That does **not** mean the wallet key replaces the TLS private key. It means the
certificate and the wallet identity are bound together in a way that a verifier
can check independently.

## How a Server Proof Works

For a server deployment, the intended verification flow is:

1. Validate the X.509 certificate chain as normal.
2. Parse the certificate and extract the wallet attestation payload.
3. Verify the embedded wallet signature.
4. Compare the recovered or declared wallet public key to the expected wallet identity.

If all four checks pass, the verifier knows two things:

- the server is presenting a normal X.509 certificate acceptable to standard PKI tooling
- that certificate was also attested by the selected wallet identity

This is the bridge that lets a server prove it is both:

- part of a traditional PKI deployment
- bound to a wallet-native cryptographic identity

## Example Workflow

```javascript
import HDWalletWasm, { Curve, X509Encoding } from 'hd-wallet-wasm';

const wallet = await HDWalletWasm();
const now = Math.floor(Date.now() / 1000);

const certificateKey = wallet.x509.generatePrivateKey(Curve.P256);

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
      privateKey: wallet.utils.decodeHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      ),
      keyLabel: 'btc-root'
    }
  },
  Curve.P256,
  certificateKey,
  X509Encoding.PEM
);

const parsed = wallet.x509.parseCertificate(certificatePem);
const walletProofValid = wallet.x509.verifyWalletAttestation(certificatePem);
```

For CA-style issuance, replace `createSelfSignedCertificate()` with
`issueCertificate()` and provide the issuer certificate plus issuer private key.

## Interoperability Notes

- Certificates are standard X.509 objects that can be exported as PEM, DER, or PKCS#12.
- Wallet attestation is carried as a non-critical extension so normal certificate consumers can ignore it safely.
- Verifiers that understand `hd-wallet-wasm` can parse and validate the extra wallet proof.
- Existing TLS stacks continue to use the certificate keypair, not the wallet keypair.

## FIPS and Compliance Positioning

The certificate side of the implementation is designed around FIPS-approved
algorithm families:

- P-256 / P-384 for certificate keys
- SHA-256 / SHA-384 for certificate signing

Wallet attestations may still use non-FIPS wallet curves such as `secp256k1` or
`Ed25519`, because the point of the feature is to bind the certificate to the
real wallet identity. That is a second proof layer, not the X.509 chain itself.

## What This Is Not

This repo does **not** currently implement:

- its own CA trust store
- a full TLS handshake engine
- OCSP or CRL fetching logic
- automatic hostname verification logic outside the certificate parsing helpers

Those remain the responsibility of the host TLS stack or the surrounding
application.

## Recommended Usage

- Use P-256 or P-384 for certificate keypairs.
- Use wallet attestation only as an additional proof, not as a substitute for certificate-chain validation.
- Export PKCS#12 only when you need OS or browser keystore interoperability.
- Keep wallet private keys and certificate private keys conceptually separate even when they are linked by attestation.
- Treat the embedded wallet proof as a high-value identity binding and verify it explicitly in applications that depend on that relationship.
