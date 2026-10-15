# Changelog

## 2.1.1 (2026-10-15)

### Security

Two defects found by internal review, present in 2.1.0 and every earlier
release, are fixed. Upgrade; no data migration is needed.

- **Forged chain proofs could verify.** Several WASM exports reported failure
  with a positive error code, but their JS wrappers treated only negative values
  as errors. When secp256k1 public-key recovery failed, `curves.secp256k1.recover`
  returned whatever its output buffer still held, which right after a genuine
  verification is the key that verification recovered. `verifyChainProof`
  compares the recovered key with the proof's `PUBLIC_KEY`, so a Bitcoin or
  Ethereum chain proof (`secp256k1-compact-bitcoin` / `-ethereum`) whose
  signature recovers to no key at all could be accepted as signed by an identity
  whose genuine proof had just been checked, without that identity's private key.
- **Invalid private keys returned heap memory.** `curves.secp256k1.sign` with a
  private key of 0 or at least the curve order n returned WASM heap bytes, which
  can include other secrets, as a "signature"; `signRecoverable` returned
  garbage with an impossible recovery id; `publicKeyFromPrivate` returned the
  encoding `02‖00…` instead of an error; secp256k1/P-256/P-384 ECDH with an
  invalid key or peer point returned uninitialised memory as the shared secret.
  The same positive-code pattern let the aligned batch exports, `checkWord` /
  `suggestWords` with an unsupported language and the `hkdf` / `pbkdf2` /
  `scrypt` / hash wrappers mistake an error code for a length or a count.

The fix:

- One return convention for the native exports. An export whose success is a
  byte length, a count or a 1/0 verdict now fails with a negative `-ErrorCode`,
  never a positive one, and zeroes its output buffer; an export whose success is
  0 fails with any other value, as before. Every JS wrapper accepts exactly the
  documented success value and throws `HDWalletError` on anything else, so no
  error path returns buffer contents.
- `publicKeyFromPrivate`, `sign`, `signRecoverable` and `ecdh` (secp256k1, P-256,
  P-384) throw `INVALID_PRIVATE_KEY` for a key outside 0 < d < n, checked in
  native code before the key is used; a key of the wrong length is refused
  before it reaches WASM.
- `curves.secp256k1.recover` takes recovery ids 0-3 only and throws when no key
  recovers, including ids 2 and 3 when r + n ≥ p. Chain-proof headers keep the
  standard Bitcoin/Ethereum meaning (27-34: recovery id 0-3, compressed or not).
- Hardening: the libsecp256k1 context (now one, shared) is blinded with
  `secp256k1_context_randomize`, seeded from the library's secure RNG. Blinding
  changes no output.
- The wrappers wipe plaintext and key buffers (AES-GCM, AES-CTR, ECIES, aligned
  batches) before freeing them; AES-GCM decryption zeroes unauthenticated
  plaintext when the tag does not match; `ethereum.tx.createEIP1559` throws on a
  `to` address that does not parse instead of building a transaction with no
  recipient.
- C/WASI callers: these exports now fail with negative codes —
  `hd_hash_*`, `hd_kdf_*`, `hd_curve_pubkey_from_privkey`,
  `hd_curve_decompress_pubkey`, `hd_secp256k1_sign` / `_sign_recoverable` /
  `_recover` / `_verify`, `hd_p256_*` / `hd_p384_*`, `hd_ecdh_secp256k1` /
  `_p256` / `_p384`, `hd_aes_gcm_*`, the coin `*_verify_message` /
  `hd_cosmos_verify_signature` exports, `hd_mnemonic_check_word`,
  `hd_mnemonic_suggest_word` and the `hd_aligned_*` exports. Callers that test
  for `< 0`, as the bundled Go, Rust, Python and Dart bindings do, are unaffected.

Every defined output is unchanged: the reviewer's fixed-vector set (1,831 values)
and the WASI vectors match 2.1.1 before this fix byte for byte; only results that
used to come from an error path now throw. Regression tests cover forged proofs,
keys 0, n and n + 1, invalid recoveries, the raw exports' codes and zeroed
outputs, and a failure path for every wrapper audited. Two existing tests used
P-256 points that are not on the curve and passed only because of this defect;
they now use the real points.

### A smaller module; no output change

Every key, address, signature and recovered key is byte for byte what 2.1.0
produced: RFC 6979 secp256k1 signatures, recoverable signatures and recovered
keys, BIP-39 seeds, BIP-32/BIP-44 keys and addresses, P-256/P-384/Ed25519
signatures, ECDH secrets, message and transaction signatures, and the frozen
single-hash cross-language vectors, checked from both the JS package and the
WASI module. The API, the export names and the files each npm package ships
are unchanged (the content-hashed wallet-origin host assets in `hd-wallet-ui`
take new names because their bytes changed); only error paths change, as
described under Security.

- libsecp256k1 (v0.7.1) is built with its smallest precomputed tables
  (`SECP256K1_ECMULT_WINDOW_SIZE` 4, `SECP256K1_ECMULT_GEN_KB` 2) instead of the
  desktop defaults (15, 86 KiB), which were about 1.1 MB of the module's data.
- The site (wallet.spacedatanetwork.org, `docs/`) loads the WASM as its own
  hashed `.wasm` file (served as `application/wasm`) instead of base64 inside
  the JS chunk. The site build refuses a `.wasm` that is not the one inside the
  npm `dist/hd-wallet.js`. The npm packages keep the single-file loader.

| Artifact (bytes) | 2.1.0 | 2.1.1 |
| --- | ---: | ---: |
| Browser WASM (in `dist/hd-wallet.js`, the site, wallet-origin) | 3,868,616 | 2,709,127 |
| ... data section | 1,966,834 | 829,503 |
| ... gzip -9 / brotli 11 | 2,265,051 / 2,027,439 | 1,128,212 / 891,581 |
| `dist/hd-wallet.js` (npm, single file) | 5,281,605 | 3,735,621 |
| `dist/hd-wallet-wasi.wasm` (npm) | 3,033,087 | 1,889,243 |
| Site wallet chunk: JS + WASM | 5,229,517 + 0 | 71,757 + 2,709,127 |
| Site assets, gzip -9 | 2,857,418 | 1,357,204 |
| Site assets, brotli 11 | 2,482,438 | 1,087,877 |
| `hd-wallet-wasm` tarball | 4,643,086 | 2,367,066 |
| `hd-wallet-ui` tarball | 2,515,476 | 1,380,907 |

gzip is zlib level 9 and brotli is quality 11 (Node's zlib); the site totals
cover the files directly in `docs/assets/`; tarball sizes are `npm pack` with
npm 11.16.0.

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
