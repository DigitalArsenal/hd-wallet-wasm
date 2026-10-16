# hd-wallet-ui

Browser UI and public relay clients for the Space Data Network wallet. The
package keeps credential entry and key operations on the dedicated wallet
origin while giving registered SDN sites a small, typed API for login, account,
and signed approval requests.

## Install

```sh
npm install hd-wallet-ui@2.1.0
```

`hd-wallet-wasm` 2.1.0 is the package's only runtime dependency.

## Published surfaces

The package exposes exactly these eight entry points:

| Import | Purpose |
| --- | --- |
| `hd-wallet-ui` | Compatibility controller with `createWalletUI()` and `init()` |
| `hd-wallet-ui/account` | `createAccountView()`: the account view shell (identity bar, section tabs) for hosts that render their own sections |
| `hd-wallet-ui/client` | Generic registered-site client |
| `hd-wallet-ui/client/sdn` | Typed SDN login client |
| `hd-wallet-ui/client/asset-review` | Typed asset-review approval client |
| `hd-wallet-ui/client/callback` | Registered callback-page completion helper |
| `hd-wallet-ui/styles` | Namespaced public-client styles |
| `hd-wallet-ui/wallet-origin` | Installed wallet-origin application API |

Internal source modules are not public package APIs.

## Add Login and Account buttons

```js
import { createWalletClient } from 'hd-wallet-ui/client';
import 'hd-wallet-ui/styles';

const wallet = createWalletClient({ clientId: 'sdn-landing-web-v1' });

const unsubscribe = wallet.subscribe((snapshot) => {
  loginButton.hidden = snapshot.status === 'connected';
  accountButton.hidden = snapshot.status !== 'connected';
});

loginButton.addEventListener('click', async () => {
  const publicIdentity = await wallet.connect();
  console.log(publicIdentity.accountPeerId);
});

accountButton.addEventListener('click', () => wallet.openAccount());

// On page teardown:
unsubscribe();
await wallet.destroy();
```

Use the client ID registered for the calling origin. An unknown client, origin,
callback, operation, or audience fails closed.

Importing a client module and constructing, inspecting, subscribing to, or
destroying a client does not read browser storage, install a callback listener,
open a window, request entropy, or contact the network. The first valid command
activates the one-shot callback channel before any popup or network work.

## Typed requests

Use `createSdnWalletClient()` for SDN authentication requests and
`createAssetReviewWalletClient()` for authority activation and approve or
disapprove attestations:

```js
import { createAssetReviewWalletClient } from 'hd-wallet-ui/client/asset-review';

const wallet = createAssetReviewWalletClient();
const signature = await wallet.requestAssetReviewApproval(reviewRequest);
await wallet.destroy();
```

Request objects are validated against the frozen protocol contract before the
wallet window opens. The caller receives only a public identity or a bounded
signature response; credential material and signing keys remain on the wallet
origin.

## Callback page

Deploy the generated `dist/browser/wallet-callback.html` and its adjacent
`sdn-wallet-callback.js` unchanged at each registry callback URI. The generated
HTML binds the script with subresource integrity and a restrictive content
security policy.

For a custom callback shell, use
`completeWalletCallbackV1()` from `hd-wallet-ui/client/callback` and pass its
location, storage, history, and close capabilities explicitly.

## Wallet origin

Deploy `dist/wallet-origin-host/` as immutable HTTPS content at the registered
wallet origin. Its HTML references only content-hashed local JavaScript, CSS,
and WebAssembly assets, binds each asset with integrity metadata, and ships a
deny-by-default content security policy.

The wallet origin presents a username and basic password form. The optional
WebAuthn PRF “Remember” control is available only there. Once authenticated, the
same surface becomes Account and provides explicit logout. Calling sites never
render or receive those credential fields.

Bundler integrations that mount the origin application directly may use:

```js
import { createWalletOriginApp } from 'hd-wallet-ui/wallet-origin';

const app = createWalletOriginApp({ wasm: initializedWallet });
await app.start();
// Later:
await app.logout();
await app.stop('page-teardown');
```

## Compatibility controller

Existing integrations may use the root entry point:

```js
import { createWalletUI } from 'hd-wallet-ui';

const controller = await createWalletUI({ wasm: initializedWallet });
await controller.openLogin();
await controller.openAccount();
await controller.logout();
await controller.destroy();
```

New registered sites should prefer the public clients because their request
and response boundaries are narrower.

## Account view (wallet site)

The wallet's own site (`index.html` and `src/app.js`, built into the
repository's `docs/` by `npm run build:docs`) shows the account as a
full-width page panel under the SDN header (`#account-view`), not a dialog.
It has five sections, each its own pane:

| Section | What it does |
| --- | --- |
| Profile | Name, photo and contact details, and **Download contact card**: a signed SDS `$EPM` (`<name>.epm`) with the account's Ed25519 signing key, X25519 encryption key, `/p2p/<peerId>` address and chain proofs. It never carries an xpub or a private key. |
| Messages | **Sign** writes `<name>.rec` (the content, `$REC{$PNM}` and a trailer) and a detached `<name>.pnm`. **Encrypt** writes `<name>.enc` (AES-256-GCM over a `$FIL`, X25519 and HKDF-SHA256, optionally signed inside). **Verify** and **Decrypt** read them. The Go SDN node and `space-data-module-sdk` read and write the same bytes. |
| People | Contacts imported from `.epm` cards (signature, peer ID and chain proofs checked), merged with on-chain trust records; publish and revoke trust. |
| Assets | The account's Bitcoin, Ethereum and Solana addresses and balances, Receive (QR) and Bitcoin/Ethereum Send. |
| Settings | Display currency, the account number (0–99), xpub and on-request xprv export, Sign out, and Forget this wallet on this device. |

The view is routed by `location.hash` (`#account/profile`, `#account/messages`,
`#account/people`, `#account/assets`, `#account/settings`); Close, Escape and
browser Back close it. Every key is derived from the seed per operation, in
the one `hd-wallet-wasm` instance, and zeroed afterwards; only public keys are
kept. Per-seed data (profile, contacts, trust history) is stored under
`hdw:<fp>:…`, where `fp` comes from a SHA-256 of the root xpub, so two seeds in
one browser never share it. Profile and Messages need a seed-phrase (or
password) session; an external wallet sees People's trust records and Assets.

### Sending

Send parses the recipient exactly (Ethereum: `0x` and 40 hex digits, EIP-55
checked when mixed case, never the zero address; Bitcoin: a mainnet P2PKH,
P2SH, P2WPKH, P2WSH or P2TR address) and the amount as a decimal string in
integer base units. **Review** builds the unsigned transaction and shows the
recipient and amount decoded from its bytes; **Send** signs that plan and
broadcasts only if the signed bytes decode to the same values. Bitcoin input
values come from the previous transactions' raw bytes (their hash must equal
the txid), never from an API's balance figures.

### Password sign-in

New password wallets use the memory-hard `password-scrypt-v2` profile
(scrypt N=2^16, r=8, p=1 over the canonical username, the same derivation the
native hd-wallet profile and the wallet origin use, cross-checked against it).
Sign-in needs a password that zxcvbn estimates at 10^20 guesses or more, for
example five or more uncommon random words. A password wallet is only as
strong as its password, and there is no recovery.

Wallets made with the old password method (SHA-256 and HKDF, before 3.0) are
not lost. **Sign in with old password method** opens them read-only with the
same username and password. Assets then offers **Move your funds to a new
wallet**: choose a new password, review and send each Bitcoin and Ethereum
balance to the new wallet, then sign in with the new password. The old method
keeps working read-only, so anything left behind (Solana for now) stays
reachable.

### Page security

The published page carries a strict Content-Security-Policy in a `<meta>` tag
(scripts and styles from its own origin only, no inline script or style, no
eval, network requests only to the chain and price APIs it uses). A `<meta>`
policy cannot set `frame-ancestors`, so the page refuses to start inside a
frame; serving it from a host that sends `frame-ancestors 'none'` is stronger.

The site's `init({ onLogin })` calls `onLogin` after login and after every
account switch with `{ xpub, peerId, signingPublicKey, encryptionPublicKey,
account }`: `peerId` is the libp2p peer ID of the account's Ed25519 identity
key (`m/44'/0'/N'/0'/0'`), `signingPublicKey` is that key and
`encryptionPublicKey` the X25519 key at `m/44'/0'/N'/1'/0'`. This peer ID is
not the one an SDN node's mnemonic sign-in derives for the same seed. No
private key is ever passed.

Hosts that render their own sections can use the same shell from
`hd-wallet-ui/account`: `createAccountView({ peerId, avatar, status, tabs })`
draws the identity bar (avatar, name, short peer ID with Copy, status, Close)
and the Profile · Messages · People · Assets · Settings tabs
(`DEFAULT_ACCOUNT_TABS`). See `CHANGELOG.md` for the changes from 2.x.

## Build and verify

```sh
npm run build:release
npm test
npm run test:browser
```

The release build cleans only this package's `dist/` directory. Repository
release checks also install packed core and UI tarballs into an external
consumer project, resolve every export, type-check representative calls, and
scan the public bundle boundary.

## License

Apache-2.0. See `LICENSE`.
