# Repository Cryptography Rules

- Keep passwords, seeds, mnemonics, PRF output, wrapping keys, private keys,
  and native secret handles on the isolated wallet origin.
- Implement identity derivation, KDF, hashing, canonical signing, key IDs,
  AEAD, and signature verification in native code exported through WASM.
- No generic signing API: every signing capability needs a purpose-labeled
  operation ID, exact request schema, wallet-owned confirmation, registry row,
  frozen cross-language vectors, and verifier.
- A controller captures its own key handles and generation. It must never
  re-read mutable module-global secret state.
- Fail closed on unknown schemes, profiles, operations, fields, encodings,
  warnings, derivation paths, or storage versions; never reinterpret a key.
- Use mutable byte buffers and native zeroization/drop APIs for secret
  material. Revoke and destroy on success, error, cancel, replacement,
  logout, pagehide, freeze, and BFCache restore.
- Keep legacy profiles explicitly named and vector-tested. Legacy fast
  password identities cannot derive or authorize asset-review approval keys.
- WebAuthn Remember Wallet is PRF-only. Credential IDs, PINs, timestamps,
  Math.random, and caller bytes are never key material or entropy.
- Use fixture-only tests. Never fetch vectors, dependencies, or services from
  a live endpoint during a test.
- Release both npm packages at one exact version and verify packed exports,
  declarations, ancestry, integrity, and clean-consumer imports before tagging.
