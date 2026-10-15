# Changelog

## 2.1.1 (2026-10-15)

### A smaller module; no API or output change

Every key, address, signature and recovered key is byte for byte what 2.1.0
produced: RFC 6979 secp256k1 signatures, recoverable signatures and recovered
keys, BIP-39 seeds, BIP-32/BIP-44 keys and addresses, P-256/P-384/Ed25519
signatures, ECDH secrets, message and transaction signatures, and the frozen
single-hash cross-language vectors, checked from both the JS package and the
WASI module. The API, the exports and the files each npm package ships are
unchanged (the content-hashed wallet-origin host assets in `hd-wallet-ui` take
new names because their bytes changed).

- libsecp256k1 (v0.7.1) is built with its smallest precomputed tables
  (`SECP256K1_ECMULT_WINDOW_SIZE` 4, `SECP256K1_ECMULT_GEN_KB` 2) instead of the
  desktop defaults (15, 86 KiB), which were about 1.1 MB of the module's data.
- The site (wallet.spacedatanetwork.org, `docs/`) loads the WASM as its own
  hashed `.wasm` file (served as `application/wasm`) instead of base64 inside
  the JS chunk. The site build refuses a `.wasm` that is not the one inside the
  npm `dist/hd-wallet.js`. The npm packages keep the single-file loader.

| Artifact (bytes) | 2.1.0 | 2.1.1 |
| --- | ---: | ---: |
| Browser WASM (in `dist/hd-wallet.js`, the site, wallet-origin) | 3,868,616 | 2,712,750 |
| ... data section | 1,966,834 | 829,353 |
| ... gzip -9 / brotli 11 | 2,272,794 / 2,027,439 | 1,138,713 / 892,958 |
| `dist/hd-wallet.js` (npm, single file) | 5,281,605 | 3,740,449 |
| `dist/hd-wallet-wasi.wasm` (npm) | 3,033,087 | 1,893,643 |
| Site wallet chunk: JS + WASM | 5,229,517 + 0 | 71,757 + 2,712,750 |
| Site assets, gzip -9 | 2,844,495 | 1,369,225 |
| Site assets, brotli 11 | 2,482,438 | 1,088,665 |
| `hd-wallet-wasm` tarball | 4,643,086 | 2,365,219 |
| `hd-wallet-ui` tarball | 2,515,476 | 1,381,119 |

The smaller tables cost a little speed where libsecp256k1 multiplies points
(Node 24, Apple M3 Ultra, median per call): `signRecoverable` 44 to 61 us,
`recover` 94 to 112 us, a five-level BIP-32 derivation 211 to 255 us, a public
child derivation 71 to 76 us. `curves.secp256k1.sign` / `verify` and
`publicKeyFromPrivate` do not go through those tables and are unchanged.

## 2.1.0 (2026-10-14)

### Breaking: every ECDSA signature hashes once

secp256k1/P-256 signatures from 2.0.x EPM attestation and sdn-plugin signing were
ECDSA over SHA-256(SHA-256(m)); now single SHA-256, DER for EPM; old signatures no
longer verify. There is no compatibility path: a double-hashed signature fails
verification. Re-sign anything signed with 2.0.x.

- `curves.secp256k1.sign` / `verify` and `curves.p256.sign` / `verify` hash their
  input with SHA-256, and `curves.p384.sign` / `verify` with SHA-384. Pass the
  message, never a hash of it. `curves.secp256k1.signRecoverable` and `recover`
  take a 32-byte hash and use it as given. The functions are unchanged; the
  README, `wasm/README.md`, JSDoc and `index.d.ts` now say so, and the examples
  that passed a digest are fixed.
- EPM attestation (`signEPMContent` / `verifyEPMSignature`, curve `secp256k1`):
  the signature is DER-encoded ECDSA over SHA-256 of the canonical content, as the
  SDS EPM annex and SDN's Go and C++ verifiers require. 2.0.x signed
  SHA-256(SHA-256(content)) in compact form, which those verifiers rejected.
  `verifyEPMSignature` accepts only strict DER over the single hash.
- Chain proofs: Bitcoin proofs sign the Bitcoin signed-message hash
  (`\x18Bitcoin Signed Message:\n` prefix, double SHA-256 as the protocol defines)
  and Ethereum proofs the EIP-191 `personal_sign` Keccak-256 hash, each as a
  65-byte compact recoverable signature (header 31 + recovery id, r, s). 2.0.x
  hex-encoded a `{ signature, recoveryId }` object and signed SHA-256(payload).
  `verifyChainProof` hashes with the chain's protocol, recovers the key and
  compares it with `PUBLIC_KEY` (Ethereum proofs must be low-S), as SDN's Go
  verifier does.
- sdn-plugin `sign_detached` / `verify_detached` (`secp256k1-sha256`): sign and
  verify the message bytes, hashed once. A caller `digest` other than
  SHA-256(message) is refused. A `walletSign` capability receives the message
  (`digest: null`) for secp256k1 and must sign it with one SHA-256.
- New helpers: `compactSignatureToDer`, `bitcoinSignedMessageHash`,
  `ethereumPersonalSignHash` (root and `hd-wallet-wasm/attestation`).

### Fixed: transaction signatures

- Bitcoin transactions (P2PKH, P2WPKH, P2SH-P2WPKH) signed the sighash through
  Crypto++ `ECDSA<ECP, SHA256>`, which hashed it again, with a random k, and
  emitted IEEE P1363 bytes labelled DER. They now sign the sighash as given with
  RFC 6979 and low-S, in strict DER. Verified against the BIP-143 native P2WPKH
  example signature.
- Ethereum transactions had the same re-hash and a fixed recovery id. They now
  sign the Keccak-256 signing hash as given and encode the real recovery id in
  `v`. Verified against the EIP-155 example and a recovery-id-1 vector.
- The native (non-libsecp256k1) `coins::ecdsaSign` / `ecdsaVerify` fallback used
  the same re-hashing signer and parsed P1363 as DER; it now uses the RFC 6979
  ecdsa module.
