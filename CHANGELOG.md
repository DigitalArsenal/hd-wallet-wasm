# Changelog

## Unreleased: hd-wallet-ui account view (breaking, for 3.0.0)

These changes break the `hd-wallet-ui` host contract, so they ship in 3.0.0.
The repository releases every package at one version (root, core, UI and
relay; see `scripts/test-version-contract.mjs` and the wallet-origin style
marker), so the version number moves for all of them together when 3.0.0 is
cut, not in this change.

The account dialog is replaced by a full-width account view under the SDN
header with five sections: Profile, Messages, People, Assets and Settings.
Messages sign, verify, encrypt and decrypt Space Data Standards files with the
account's SDN identity keys, and the contact card is a signed SDS `$EPM`.
`hd-wallet-wasm` stays the only runtime dependency (2.1.0; pin 2.1.1 when it is
released, see the Send notes below).

### Breaking: host contract

- `onLogin` receives `{ xpub, peerId, signingPublicKey, encryptionPublicKey, account }`.
  - `peerId` is the libp2p peer ID of the account's Ed25519 SDN identity key
    (`m/44'/0'/N'/0'/0'`, SLIP-10). In 2.x it was the root secp256k1 key's
    peer ID. It is also not the peer ID an SDN node's mnemonic sign-in derives
    for the same seed (that uses the BIP-32 scalar at `m/44'/0'/0'/0/0` as an
    Ed25519 seed), so a host must not match wallet users to node accounts by
    this value. Signatures still verify across the two, because the key
    travels in the peer ID.
  - `signingPublicKey` is that Ed25519 key. In 2.x it was the Solana key.
  - `encryptionPublicKey` is new: the X25519 key at `m/44'/0'/N'/1'/0'`.
  - `account` is new: the BIP-44 account number N.
  - Switching the account number in Settings calls `onLogin` again with the
    new identity.
- `init()` resolves to `{ openAccount, closeAccount, openLogin, logout, destroy }`.
  In 2.x it resolved to nothing. `openAccount(section?)` opens
  `#account/<section>`. The demo page passes these controls to
  `window.__sdnWalletReady`.
- The `autoOpenWallet` option and `window.__sdnAutoOpen` are removed.
- The view is routed by `location.hash`: `#account/profile`, `#account/messages`,
  `#account/people`, `#account/assets` and `#account/settings`. Close and
  browser Back clear the hash. While the view is open, the page's `<main>` and
  `<footer>` are `inert`.

### Breaking: `hd-wallet-ui/account` (`createAccountView`)

- `DEFAULT_ACCOUNT_TABS` is `profile`, `messages`, `people`, `assets`,
  `settings` (labels Profile, Messages, People, Assets, Settings).
- The `bond`, `wallets`, `activeWalletId` and `onWalletChange` options, and
  the `AccountViewBond` and `AccountViewWallet` types, are removed. The header
  has no wallet selector and no Bond.
- New options `peerId` (shown short, copied in full), `avatar` (`{ url?, initials? }`)
  and `status` (the quiet status word). `update()` takes the same fields.

### Breaking: template and styles

- `#account-view` and its `#account-tab-*` / `#account-pane-*` elements replace
  `#keys-modal`. The old dialog ids are gone, including `account-wallet-select`,
  `wallet-bond-value`, `wallet-manage-tab`, `wallet-wallets-view`,
  `wallet-main-view`, `messaging-key-type`, `generate-vcard`,
  `vcf-import-input` and the `pki-*`, `alice-*` and `bob-*` demo controls.
- New `styles/account.css` (imported by `main.css`) defines the SDN tokens
  (`--bg`, `--text`, `--text-2`, `--muted`, `--border`, `--accent`, `--alert`
  and the rim set) with a real light theme under `[data-theme="light"]`.
  The `--white-NN` variables, the `.modal-tab` account tabs and the removed
  sections' rules are gone from `main.css`. The demo page no longer sets
  `data-sdn-light="invert"`.

### Breaking: removed features

- `$EME` messages, including decrypt, and the key-type and HD-path controls.
  Messages use the Ed25519 and X25519 SDN identity keys only.
- vCard export and import (`vcard-signing.js`, the vCard QR), replaced by the
  `$EPM` contact card. The `vcard-cryptoperson` devDependency is removed.
- The multi-wallet list (ten padded entries, renames, active flags) and the
  Advanced custom-path accounts. One account number (0–99) in Settings selects
  the identity, peer ID, contacts and addresses.
- Trust rules, the Trust Levels legend, the `.sds.json` trust export and
  import, and the 3-minute background trust poll. People scans when opened
  (at most every 2 minutes) and on Refresh.
- Name resolution (Hiro, ENS `eth_call`, Bonfida), the PKI demo and its saved
  keys, the BIP-39 export button and the `.txt` key downloads.

### Breaking: storage

- Per-seed data lives under `hdw:<fp>:account` and
  `hdw:<fp>:a<N>:{profile,contacts,trust-imported-txs,trust-drain-baselines,scan-cache}`,
  where `fp` is the first 16 hex characters of SHA-256 of the root xpub. Two
  seeds in one browser no longer share a profile, contacts or trust history.
- The first seed login after the upgrade moves the 2.x profile
  (`hd-wallet-vcard-identity`) and trust history into account 0, then deletes
  `hd-wallet-wallets`, `hd-wallet-active-accounts`, `hd-wallet-vcard-identity`,
  `hd-wallet-messaging-key-config-v1`, `hd-wallet-scan-balance-cache-v1`,
  `trust-rules`, `trust-imported-txs`, `trust-drain-baselines`,
  `wallet-pki-keys` and `bond-currency`. The currency moves to `hdw-currency`.
- Private keys are never stored. They are derived per operation and zeroed
  afterwards.

### Security: Send (SEC-014, SEC-057)

- The Ethereum recipient must be exactly `0x` and 40 hex digits; mixed case
  must pass EIP-55; the zero address is refused. 2.x enabled Review for any
  text longer than 10 characters, and hd-wallet-wasm 2.1.0 signed an
  unparsable recipient (an ENS name, 39 or 41 digits, a stray character, a
  Bitcoin address) as a transfer to the zero address: the ETH was burned.
- Amounts are parsed as decimal strings into integer base units with BigInt.
  2.x used `Math.round(amount * 1e18)` (precision lost above 2^53 wei) and
  2.1.0 wrapped values of 2^64 wei and more (20 ETH was signed as about 1.55).
- The value reaches hd-wallet-wasm as 32 bytes on every installed version:
  the page encodes the exact unsigned EIP-1559 fields (every integer
  range-checked, a 20-byte recipient, no contract creation) and the WASM
  parses them, instead of passing the amount through 2.1.0's uint64 setter.
  20 ETH is sent as 20 ETH; amounts of 2^256 wei or more are refused. Trust
  records use the same builder.
- Review builds the unsigned transaction and shows the recipient, amount and
  fee decoded from its bytes. Send signs exactly the reviewed plan, decodes
  the signed bytes and refuses to broadcast unless every field matches, so a
  builder that drops the recipient or wraps the value is caught whatever
  hd-wallet-wasm version is installed. The chain ID is fixed to mainnet, a
  base fee above 1,000 gwei is refused, and the RPC's transaction hash must
  equal the hash of the signed bytes.
- Bitcoin Send works again (2.x called the builder with the wrong arguments,
  so every send threw). Each UTXO's value is read from its previous
  transaction, fetched raw and checked against the txid, and its output must
  pay this account; an API's figures are never spent. A legacy signature does
  not commit to input values, so a lying API could otherwise have turned the
  balance into a miner fee. Trust publishing uses the same verified UTXOs.
- The change-address helper paid a P2SH (`3…`) address with a P2PKH script; it
  now writes the script the address encodes, and refuses anything else.

### Security: password sign-in (SEC-015)

- New password wallets derive through the memory-hard `password-scrypt-v2`
  profile (scrypt N=2^16, r=8, p=1, salt `sdn-hd-wallet/password-scrypt-v2`,
  NUL, canonical username), with the native username canonicalization,
  length (12–128 characters) and common-password policy. The page derives the
  seed with the WASM scrypt and refuses to sign in unless its `m/44'/0'/0'`
  xpub equals the native profile's.
- Sign-in requires a zxcvbn estimate of at least 10^20 guesses (pinned
  `@zxcvbn-ts/core` 4.2.0 with the common and English dictionaries, loaded
  only when the password form opens). The 2.x meter counted character classes
  and called `passwordpasswordpassword` strong; the only gate was 24
  characters.
- The password field no longer asks the browser to save it
  (`autocomplete="off"`).
- **Migration.** A password wallet made with 2.x derives different addresses
  under the new profile. Its funds stay reachable: **Sign in with old password
  method** (under "Made your wallet with a password before version 3.0?")
  opens it with the old derivation, read-only. Assets then shows **Move your
  funds to a new wallet**: choose a username and new password (estimated and
  typed twice), and the page derives the new wallet's addresses; **Move all
  BTC** / **Move all ETH** build a sweep to exactly those addresses, shown
  decoded for review. Sign in with the new password afterwards. A read-only
  session signs nothing else (no messages, contact cards or trust records),
  and a sweep can only pay the new wallet derived on that page. Moving SOL is
  not supported yet; the old method keeps working, so SOL stays reachable.

### Security: page (SEC-053, SEC-054, SEC-020, SEC-039, SEC-071)

- The page has a strict Content-Security-Policy `<meta>` tag: `default-src
  'none'`, scripts and styles from the page's origin only (`'wasm-unsafe-eval'`
  for the WASM), images from the origin, `data:` and `blob:`, and
  `connect-src` limited to blockchain.info, blockstream.info,
  cloudflare-eth.com, the publicnode Ethereum and Solana RPCs,
  api.mainnet-beta.solana.com, api.coinbase.com and api.coingecko.com. The
  inline scripts moved to `src/landing.js` and `src/landing-nav.js`, inline
  style attributes to classes, and the AI-credits panel's CSS to
  `assets/ai-credits/ai-credits.css`. GitHub Pages cannot send
  `frame-ancestors` and a `<meta>` policy cannot carry it, so the page refuses
  to start inside a frame.
- The chain icons are self-hosted copies pinned to a spothq/cryptocurrency-icons
  commit (CC0) instead of `cdn.jsdelivr.net/...@master`.
- Every address the page shows or sends from is derived from the seed when the
  account opens; storage holds none the page reads back (2.x showed a previous
  seed's stored address).
- Verify shows a `$PNM`'s date as a claim ("signed separately from the
  content") and its file name as "not signed", and warns before saving under
  that name; a `$PNM` signs the content's CID and the timestamp separately and
  does not cover the file name. Decrypt notes that a signature covers the
  content, not the recipient, so a signed file may have been forwarded.
- Section titles (focused after a section switch, `tabindex="-1"`) draw no
  focus box when the focus is programmatic after a click
  (`:focus:not(:focus-visible)`); after a keyboard choice the outline stays.
- Balances and prices are looked up when Assets opens or on Refresh balances,
  not at sign-in or on an account switch (SEC-054): each lookup sends the
  account's addresses, with the user's IP, to a third-party API.

### Security: secrets on screen and on the clipboard (SEC-081)

- The seed-phrase word slots are password fields until **Show words** (or
  Generate, whose new phrase has to be written down); clearing the slots masks
  them again. Mobile keyboards do not learn the words, and password managers
  are told to ignore the fields.
- A copied account xprv is overwritten on the clipboard after 30 seconds
  (retried when the window next gets focus if the browser refuses the write),
  and at once on sign-out. The page says clipboard history or sync can still
  keep a copy.

### Security: contact cards (SEC-002, SEC-036, SEC-056)

- Bitcoin and Ethereum chain proofs on an imported card are verified a second
  time outside the WASM (ECDSA over the chain's signed-message digest, with
  the header's recovery id). hd-wallet-wasm up to 2.1.0 returned the previous
  recovery's key when a recovery failed, so a card could list someone else's
  real proof followed by a proof with a garbage signature and claim that
  person's address for its own key.
- A contact's name and details are labelled as what the card's owner typed;
  the card proves only the peer ID, keys and listed addresses.
- Encrypt and Decrypt refuse an all-zero or malformed X25519 shared secret
  themselves, whatever the WASM returns.

### New: SDS envelopes (`src/envelopes.js`)

- Sign writes `<name>.rec` (content, `$REC{$PNM}` and the 8-byte trailer) and
  `<name>.pnm` (a size-prefixed `$PNM` over the content's CIDv1). The signature
  is Ed25519 over the CID string, as `sds.VerifySDSSignature` checks.
- Encrypt writes `<name>.enc`: AES-256-GCM over a size-prefixed `$FIL`, with the
  `$REC{$ENC}` trailer (X25519, HKDF-SHA256, context
  `space-data-network/wallet/message/v1`). "Sign it" puts a `$PNM` over the
  `$FIL` inside the ciphertext.
- Verify and Decrypt read these files, and Decrypt also opens module-sdk
  `encryptBytesForRecipient` output.
- The contact card (`<name>.epm`) is a size-prefixed `$EPM` signed with the
  Ed25519 identity key. It carries the Ed25519 Signing key, the X25519
  Encryption key, `/p2p/<peerId>` and Bitcoin, Ethereum and Solana chain proofs.
  It never carries the account xpub (the chain proofs' payload has an empty
  `xpub`), so a card does not reveal the account's other addresses. Profile
  text drops control characters, U+2028/U+2029 and bidi overrides, which keeps
  the card's canonical JSON identical to what the Go node signs and checks.
  Importing a card checks its signature, its peer ID and every chain proof.
- The bytes match module-sdk 0.9.7 and SDS 1.249.0, and SDN's Go node verifies
  and decrypts them. `space-data-module-sdk` is a devDependency used only by
  the conformance tests, and `spacedatastandards.org` is pinned at 1.249.0.

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
