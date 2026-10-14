# Changelog

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
