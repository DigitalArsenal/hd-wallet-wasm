# Changelog

## 2.1.1 (2026-10-15)

### Security

Defects found by internal review, present in 2.1.0 and every earlier release,
are fixed. Upgrade; no data migration is needed, but **rotate every P-384 key
that has signed with an affected version** (first item).

- **P-384 signatures exposed the private key (critical).** The RFC 6979 nonce
  generator sized its V and K buffers to the message hash (48 bytes for P-384)
  but always filled them with HMAC-SHA256 (32 bytes), so the last 16 bytes of
  every P-384 nonce k were the constant `01 01 … 01`. A nonce with 128 known
  bits is a hidden-number problem: a handful of P-384 signatures by one key
  recover that key by lattice reduction. Affected: `curves.p384.sign` (and the
  `hd_p384_sign` export, also in the WASI module) in hd-wallet-wasm 1.2.7
  through 2.1.0 (0.1.8 through 1.2.6 signed P-384 with a random nonce and are
  not affected); X.509 P-384 certificates, PKCS#12 bundles and wallet
  attestations (`x509.*` with P-384 keys) in 2.0.0 through 2.1.0; and the C++
  `ecdsa::p384Sign` in every release. **Treat every P-384 key that signed
  anything with an affected version as compromised: rotate it, reissue
  certificates and attestations it signed, and stop trusting signatures made
  with it.** secp256k1 and P-256 signing (32-byte hashes) was not affected.
- **Ethereum transactions could pay the zero address, or less than asked.**
  A transaction whose recipient never parsed (an ENS name, a truncated or
  over-long address, a stray character, a Bitcoin or Solana address) kept 20
  zero bytes as its `to` and signed as a value transfer to `0x00…00`, burning
  the value. 2.1.0's `ethereum.tx.createEIP1559` ignored the setter's error;
  `ethereum.tx.create` ignored every field but `chainId`, so it always signed a
  zero transaction to `0x00…00`. Separately, `value` went through a 64-bit
  setter, so 2^64 wei (about 18.45 ETH) or more wrapped: 20 ETH was signed as
  about 1.553 ETH. nonce, gas and fee fields wrapped the same way above 2^64.
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
- **Inputs of the wrong size reached native code.** Many exports read a
  fixed-size input (a 32- or 48-byte private key, a 33-byte public key, a 64- or
  96-byte signature, a 32-byte hash or program id) without taking its length,
  and their wrappers did not check it. A short input was completed from stale
  WASM heap memory, which could come back inside a WIF, a public key or a
  signature, or let a truncated or padded P-256/P-384 signature verify; a long
  one was silently truncated; some short keys made the wrapper's wipe write
  past its allocation and corrupt the heap. Keys were not always checked
  either: `bitcoin.toWIF` and `x509.exportPrivateKeyPem` exported scalars of 0,
  n and above, and the address builders, `libp2p.peerIdFromPublicKey` and
  `curves.compressPublicKey` accepted byte strings that are not curve points.
- **Ed25519 verification was not strict.** It accepted a second encoding of
  every signature (S + L), and keys and signature points of small order, with
  which a signature is not bound to its message.
- **ECIES decryption at the C ABI** (`hd_ecies_decrypt`, also in the WASI
  module) left the unauthenticated plaintext in the output buffer when the tag
  did not match, and reported it as -2 (INVALID_ARGUMENT). The JS wrapper
  already wiped the buffer and threw.

The fix:

- **RFC 6979 nonces as specified.** The HMAC uses the message hash function
  (HMAC-SHA256 for a 32-byte hash, HMAC-SHA384 for 48, HMAC-SHA512 for 64; any
  other hash length is refused), V and K are that HMAC's size, x and h enter as
  int2octets(x) and bits2octets(h) (h reduced mod q), and k is bits2int(T) for
  T built from whole HMAC outputs. ECDSA's z is the leftmost qlen bits of the
  hash in signing, verification and recovery. The RFC 6979 Appendix A.2.5
  (P-256) and A.2.6 (P-384) known answers for SHA-256, SHA-384 and SHA-512 are
  native tests, and the P-256/SHA-256 and P-384/SHA-384 rows (the hashes
  `curves.p256.sign` and `curves.p384.sign` apply) are WASM tests, with a check
  that no P-384 nonce ends in the old constant.
  **P-384 signatures change:** every P-384 signature now differs from 2.1.0 (it
  is the RFC 6979 signature, which every ECDSA verifier, 2.1.0 included,
  accepts).
  secp256k1 and P-256 signatures are unchanged byte for byte (the reviewer's
  secp256k1 vector set and 168 P-256 signatures compared), except that a
  P-256 SHA-256 hash at or above the group order (probability about 2^-32) now
  gets the RFC nonce.
- **An Ethereum transfer needs a recipient.** In C++ and at the C ABI a
  transaction that was never given a valid `to` (and is not an explicit
  contract creation, `setContractCreation(true)`) does not serialize, hash or
  sign: `serialize`, `serializeForSigning`, `sign` and `validate` fail with
  INVALID_ADDRESS (502). Parsing refuses a `to` field that is neither 20 bytes
  nor empty, and a value over 32 bytes, with INVALID_TRANSACTION (it read a
  malformed `to` as a contract creation). The wrappers check `to` with
  `hd_eth_tx_set_to_hex`'s result (throwing on ENS names, wrong lengths, extra
  characters and non-Ethereum addresses), always set `value` through the
  256-bit setter (any 0 ≤ value < 2^256 is encoded in full), and refuse
  negative or non-integer amounts and nonce, gas, fee or chain id values of
  2^64 or more instead of wrapping them. `ethereum.tx.create` now applies the
  documented `nonce`, `gasPrice`, `gasLimit`, `to`, `value` and `data`.
  Display the recipient and amount decoded from the built transaction, not the
  typed text, before asking for confirmation.
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
  `to` address that does not parse instead of building a transaction that
  pays `0x00…00`.
- **Input validation everywhere, one rule.** Every JS wrapper (`index.mjs`,
  `aligned.mjs`) checks every input before it reaches WASM, with one helper set
  (`dist/runtime/input-validation.mjs`): its type (binary data must be a
  `Uint8Array`, text a string, numbers integers in range), its exact length or
  allowed set of lengths, and for keys their validity, checked by two new native
  exports rather than by any curve arithmetic in JS:
  `hd_curve_validate_privkey` (the curve's scalar size, and 0 < d < n for
  secp256k1, P-256 and P-384) and `hd_curve_validate_pubkey` (SEC1 02/03/04
  encodings parsed by libsecp256k1 for secp256k1 and OpenSSL for P-256/P-384;
  hybrid 06/07 encodings, coordinates ≥ p and points off the curve are refused;
  Ed25519 keys must be canonical, decodable and not of small order). Signing,
  derivation, export, ECDH, ECIES, address and peer-ID wrappers throw
  `HDWalletError` (`INVALID_PRIVATE_KEY`, `INVALID_PUBLIC_KEY`,
  `INVALID_ARGUMENT`, `NOT_SUPPORTED` for an unsupported curve or coin) on any
  invalid input; the aligned batch buffers are zeroed before they are filled.
  ECIES no longer treats an unknown curve name as secp256k1.
- **Verification returns false, never throws, for bad bytes.**
  `curves.*.verify`, `coin.verifyMessage`, `bitcoin` / `solana` / `polkadot`
  `verifyMessage`, `cosmos.verifySignature`, the aligned `verifyBatch` entries,
  `verifyChainProof` and `verifyEPMSignature` return false for any invalid
  signature, key, hash or encoding (wrong length, not a point, malformed hex or
  base64) and throw only for a programmer error: an argument of the wrong type
  or an unknown coin or curve. `coin.verifyMessage` used to throw
  `INVALID_SIGNATURE` on a malformed signature. `ethereum.verifyMessage`
  recovers and returns the signer's address, so it still throws
  `INVALID_SIGNATURE` when no address recovers; it now takes only v = 0, 1, 27
  or 28.
- **Strict Ed25519 (RFC 8032, section 5.1.7).** A signature R ‖ S under a key A
  verifies only when it is 64 bytes and the key 32; S < L (L = 2^252 +
  27742317777372353535851937790883648493); A and R each encode y < p
  (canonical) and are none of the eight points of small order (with either sign
  bit); A decodes to a curve point; and [S]B = R + [k]A for k = SHA-512(R ‖ A ‖
  M) mod L, checked without the cofactor by comparing the encoding of
  [S]B − [k]A with R. This applies everywhere Ed25519 is verified:
  `curves.ed25519.verify`, Solana and Polkadot verification, the aligned
  batches, X.509 wallet attestations, EPM signatures and Ed25519 chain proofs.
  Every RFC 8032 test vector and every signature this library makes still
  verifies.
- **Private keys checked before export.** `hd_btc_to_wif` and the X.509 key
  paths (PEM export, certificates, PKCS#12, wallet attestations) refuse a scalar
  outside 0 < d < n in native code.
- **C ABI outputs.** `hd_ecies_encrypt` / `hd_ecies_decrypt` zero their output
  on every failure and report a tag mismatch as -VERIFICATION_FAILED (-403);
  `hd_ecdh` and the Ed25519, X25519 and SLIP-10 exports zero their output on
  failure; `hd_libp2p_peer_id*` and `hd_libp2p_ipns_hash*` take only valid
  public keys of the libp2p sizes and check the output size before writing.
  `_hd_curve_compress_pubkey` is dropped from the export list: it was listed but
  never defined, and `curves.compressPublicKey` compresses after the native
  point check.
- C/WASI callers, fixed-size inputs: the C ABI keeps its shape, so these exports
  still take no length for the inputs named and read exactly that many bytes —
  `hd_curve_decompress_pubkey` (33), `hd_p256_verify` / `hd_p384_verify` (a
  64- / 96-byte signature), the `hd_*_sign*` exports and the coin and
  transaction signers (a 32-byte key; 48 for P-384), `hd_btc_tx_add_input` (a
  32-byte txid and a 33-byte key), `hd_sol_find_pda` (a 32-byte program id),
  `hd_eth_tx_set_to` (20 bytes) and `hd_btc_tx_add_p2pkh_output` /
  `_p2wpkh_output` (a 20-byte hash). Pass buffers of exactly those sizes, and
  check keys with `hd_curve_validate_pubkey` / `hd_curve_validate_privkey`.
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

After the input validation the same vector sets still match: the WASI vectors
byte for byte, and in the JS set only the messages of four errors differ (keys 0
and n are now refused by the wrapper's check, with the same
`INVALID_PRIVATE_KEY` code). None of the vectors used a malleable Ed25519
signature. A committed fuzz test (`wasm/test/test_input_fuzz.mjs`) fills freed
WASM heap with a marker and passes 771 invalid inputs (wrong lengths, invalid
scalars, invalid points, malleable or small-order Ed25519 signatures, wrong
types, Ethereum recipients that do not parse, out-of-range transaction
integers) through 88 wrapper entry points: each throws a library error or returns
false, none returns the marker, and the module still signs and verifies
afterwards. Native tests cover strict Ed25519, the key checks, the ECIES output
on a tag mismatch and the X.509 scalar check.

Not changed, by decision: secp256k1 verification accepts high-S signatures.
`curves.secp256k1.verify`, EPM DER signatures and Bitcoin chain proofs accept a
signature whose S is above n/2, as the OpenSSL and Go `crypto/ecdsa` verifiers
they interoperate with do; refusing it would reject signatures those verifiers
accept. Every signature this library makes is low-S, and Ethereum chain proofs,
where the chain itself requires low-S, still refuse high-S.

### A smaller module; no output change

Apart from P-384 signatures (fixed, see Security), every key, address,
signature and recovered key is byte for byte what 2.1.0 produced: RFC 6979
secp256k1 signatures, recoverable signatures and recovered keys, BIP-39 seeds,
BIP-32/BIP-44 keys and addresses, P-256/Ed25519 signatures, ECDH secrets, message and transaction signatures, and the frozen
single-hash cross-language vectors, checked from both the JS package and the
WASI module. The API, the export names and the files each npm package ships
are unchanged (the content-hashed wallet-origin host assets in `hd-wallet-ui`
take new names because their bytes changed); only error paths change, as
described under Security. The export list gains `hd_curve_validate_pubkey` and
`hd_curve_validate_privkey` and drops the never-defined
`_hd_curve_compress_pubkey`, and the npm package ships one more runtime file,
`dist/runtime/input-validation.mjs`.

- libsecp256k1 (v0.7.1) is built with its smallest precomputed tables
  (`SECP256K1_ECMULT_WINDOW_SIZE` 4, `SECP256K1_ECMULT_GEN_KB` 2) instead of the
  desktop defaults (15, 86 KiB), which were about 1.1 MB of the module's data.
- The site (wallet.spacedatanetwork.org, `docs/`) loads the WASM as its own
  hashed `.wasm` file (served as `application/wasm`) instead of base64 inside
  the JS chunk. The site build refuses a `.wasm` that is not the one inside the
  npm `dist/hd-wallet.js`. The npm packages keep the single-file loader.

| Artifact (bytes) | 2.1.0 | 2.1.1 |
| --- | ---: | ---: |
| Browser WASM (in `dist/hd-wallet.js`, the site, wallet-origin) | 3,868,616 | 2,719,804 |
| ... data section | 1,966,834 | 829,614 |
| ... gzip -9 / brotli 11 | 2,265,051 / 2,027,439 | 1,132,056 / 893,303 |
| `dist/hd-wallet.js` (npm, single file) | 5,281,605 | 3,750,367 |
| `dist/hd-wallet-wasi.wasm` (npm) | 3,033,087 | 1,897,259 |
| Site wallet chunk: JS + WASM | 5,229,517 + 0 | 71,994 + 2,719,804 |
| Site assets, gzip -9 | 2,857,418 | 1,364,584 |
| Site assets, brotli 11 | 2,482,438 | 1,092,246 |
| `hd-wallet-wasm` tarball | 4,643,086 | 2,379,311 |
| `hd-wallet-ui` tarball | 2,515,476 | 1,389,312 |

The table was measured before the security fixes above; the RFC 6979 fix
links HMAC-SHA384/SHA-512 and adds about 13 KB to each WASM (browser WASM
2,719,804 → 2,733,404 bytes, WASI 1,897,259 → 1,905,350, `dist/hd-wallet.js`
3,750,367 → 3,768,499).

gzip is `gzip -9 -n` and brotli is quality 11 (Node's zlib); the site totals
cover the files directly in `docs/assets/`; tarball sizes are `npm pack` with
npm 11.16.0. The input validation under Security adds 10,677 bytes to the
browser WASM (the key-check exports and their libsecp256k1, OpenSSL and
Crypto++ calls) and 8,016 to the WASI module.

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
