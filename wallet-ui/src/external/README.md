# hd-wallet-ui/external — the external-wallet component

OWNER RULING 2026-08-19 (verbatim): "External wallet needs to be the first way
to do it, then as a backup use our wallet software."

OWNER RULING 2026-08-20: this code lives HERE, in hd-wallet-ui, and every app
consumes it "only as a component" — no app carries its own copy. Ported from
spaceaware-ui `src/dashboard/src/lib/wallet-external/` (pure modules
byte-verbatim, header relabels only; the Svelte panel became `panel.js` as a
framework-free DOM component, its rendered form the design source).

## What this is

- `accounts.js` — the normalized account contract (the ONE read-only shape).
- `discovery.js` — EIP-6963 (EVM) + Wallet Standard (Solana) discovery.
- `provider.js` — EIP-1193 connect / personal_sign / session events.
- `chains.js` — chain-id → display badge.
- `format.js` — display-only truncation (the full value stays the identity).
- `panel.js` — `createExternalWalletPanel({ mount, onConnected, ... })`, the
  mountable connect UI (semantic `hdw-ext-*` classes; default skin =
  `styles/external-panel.css`, themed via `--hdw-ext-*` custom properties).

## Zero-dependency firewall (HERMES/ARACHNE 2026-08-20)

Nothing under `src/external/` imports the HD custody world — not the wallet
core, not its crypto dependencies, not storage. An external chain account is
VALUE the user attaches, never AUTHORITY (key-role grammar, IRIS 2026-08-19);
the two worlds meet ONLY through the normalized account shape in
`accounts.js`. The lane's tests run without the emscripten toolchain.

## Standing refusals (rulings, not preferences)

- **WalletConnect / Reown: REFUSED** (IRIS 2026-08-19). Its relay is a wss
  external origin and its registry/icons are external fetches — consuming
  apps enforce zero-external-origin-bytes and this component must never be
  the reason they can't.
- **iframe / MPC wallet SDKs: structurally refused** — consumers run under
  `default-src 'self'` with no `frame-src` (ARACHNE R8).
- **UA sniffing: never.** In-app wallet browsers are detected by what they
  INJECT (EIP-6963 announces, `ethereum#initialized`, wallet-standard
  register events), never by user-agent strings.
- **Icons are data: URIs or nothing.** EIP-6963 requires a data URI; anything
  else would make the page fetch external bytes when rendered, so it is
  stripped (the wallet stays admitted, its icon does not).

## CSP delta: ZERO

Discovery is DOM CustomEvents and provider method calls on objects the wallet
already injected — no new origins, no new script, no new CSP token, no
runtime style injection (the stylesheet ships as a file consumers bundle).

## Signature custody note

`personal_sign` returns 65 bytes `[R||S||V]`. This lane passes it VERBATIM —
byte-order normalization (dcrd compact expects `[V||R||S]`) is the verifying
server's job. Solana `signMessage` output is raw Ed25519 and is NEVER
admissible as an SDN §9.1 signature (the coincidence ban) — domain separation
belongs to the admitting server's contract, not to this module.

## Honesty rules the panel keeps

- No dead buttons: a settled empty discovery renders NO WALLET DETECTED with
  the built-in wallet named as the backup method.
- Attachment chrome: "connected", never "unlocked"; no presence dot.
- The optional in-panel connected view (`connectedView: true`, used by the
  demo) shows wallet name/icon, chain badge, and the copyable address, plus a
  DISCONNECT that forgets the in-page state — it never fabricates an HD
  login and never implies server admission.
