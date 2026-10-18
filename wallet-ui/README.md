# hd-wallet-ui

Browser UI and public relay clients for the Space Data Network wallet. The
package keeps credential entry and key operations on the dedicated wallet
origin while giving registered SDN sites a small, typed API for login, account,
and signed approval requests.

## Install

```sh
npm install hd-wallet-ui@2.2.2
```

`hd-wallet-wasm` 2.2.2 is the package's only runtime dependency.

## Published surfaces

The package exposes exactly these seven entry points:

| Import | Purpose |
| --- | --- |
| `hd-wallet-ui` | Compatibility controller with `createWalletUI()` and `init()` |
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

## Sealed fields and database keys

Two registered documentation sites can ask the wallet to open data sealed to
the signed-in user's contact-encryption key (X25519, `m/44'/0'/0'/1'/0'`) with
the SDN Unified ECIES field cipher. The wallet opens it only after the user
approves, only for the site the data is bound to, and returns only the opened
bytes. Keys and shared secrets never leave the wallet.

```js
// sdn-flatbuffers-pages-v1: fields with their SDS $ENC headers.
const opened = await wallet.openFields({
  fields: [{ enc, context, fieldId, ciphertext }], // 1..16, <= 4096 B each, <= 12288 B in all
});
// [{ plaintext: Uint8Array } | { refused: 'NOT_ADDRESSED_TO_ACCOUNT' }], in order

// sdn-flatsql-pages-v1: one database's content key, an $ENC + $KMF pair.
const { contentKey } = await wallet.unwrapKey({ enc, kmf, context });
```

- `context` is the HKDF info and must equal the header's CONTEXT:
  `sdn-field-encryption/v1|<site>|<schema>|<field>|k<version>`. The site is
  `flatbuffers` for `sdn-flatbuffers-pages-v1` and `flatsql` for
  `sdn-flatsql-pages-v1` (registry rows `flatbuffers-field-open-v1` and
  `flatsql-key-unwrap-v1`). Data bound to another site is refused by the
  client and, independently, by the wallet before it asks for a password.
- The header must carry `RECIPIENT_KEY_ID` = sha256(contact public key)[:8].
  A field sealed to another key comes back `refused`; an unwrap rejects with
  `NOT_ADDRESSED_TO_ACCOUNT`.
- `contentKey` is the database's own 32-byte content key, scoped to that
  database. It is not a wallet key.
- The prompt names the site and the number of fields. "Don't ask again for
  this site" covers that site and account for 15 minutes or 20 openings,
  whichever ends first; signing out of the wallet forgets it. Every opening
  still needs the wallet unlocked.
- The wallet seals its answer to a one-use X25519 key the client makes for
  the request (the same field cipher, info `sdn-wallet-reply/v1`), so the relay
  that carries the answer never holds a plaintext. The browser needs Web
  Crypto X25519.

Pages on one origin are one security principal to the browser, so each of
these clients has its own origin (`https://flatbuffers.spacedatanetwork.org`,
`https://flatsql.spacedatanetwork.org`). The shared
`https://digitalarsenal.github.io` origin is the one client
`digitalarsenal-pages-v1`, which signs in only.

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
