# hd-wallet-wasm

WebAssembly HD-wallet runtime with typed JavaScript APIs for hierarchical key
derivation, multi-curve signing, SDN identities, aligned batch operations, and
canonical EPM attestations.

## Install

```sh
npm install hd-wallet-wasm@2.0.26
```

Use the package through a standards-compliant ESM bundler or from an installed
Node project. Production deployments should serve only artifacts emitted by a
verified package build over HTTPS.

## Published surfaces

| Import | Purpose |
| --- | --- |
| `hd-wallet-wasm` | High-level wallet initializer and typed runtime API |
| `hd-wallet-wasm/aligned` | Aligned batch-operation API |
| `hd-wallet-wasm/attestation` | Canonical EPM payload, signing, and verification helpers |
| `hd-wallet-wasm/wasm` | Low-level Emscripten module factory |
| `hd-wallet-wasm/wasi.wasm` | Canonical WASI binary |
| `hd-wallet-wasm/dist/hd-wallet-wasi.wasm` | Compatibility name for the same WASI binary |

All JavaScript and declaration dependencies needed by these surfaces are
included under the package's staged `dist/runtime/` tree. Repository source,
tests, maps, and build tarballs are excluded from the published package.

## Initialize the wallet

```js
import initializeWallet from 'hd-wallet-wasm';

const wallet = await initializeWallet();

const entropy = crypto.getRandomValues(new Uint8Array(32));
wallet.injectEntropy(entropy);

const phrase = wallet.mnemonic.generate(24);
const seed = wallet.mnemonic.toSeed(phrase, 'optional passphrase');
const master = wallet.hdkey.fromSeed(seed);
const child = master.derivePath("m/44'/0'/0'/0/0");

const digest = wallet.utils.sha256(new TextEncoder().encode('example'));
const signature = wallet.curves.secp256k1.sign(digest, child.privateKey());

wallet.utils.secureWipe(seed);
child.wipe();
master.wipe();
```

`createHDWallet()` is an equivalent named initializer:

```js
import { createHDWallet } from 'hd-wallet-wasm';

const wallet = await createHDWallet();
```

Both initializers take no configuration arguments. Package staging keeps the
high-level wrapper bound to its verified adjacent loader.

## SDN wallet-origin capability

The high-level initializer installs an immutable capability on the exact module
instance it creates. Resolve it with `getWalletOriginCapabilities()` when
mounting `hd-wallet-ui/wallet-origin`:

```js
import initializeWallet, { getWalletOriginCapabilities } from 'hd-wallet-wasm';

const wallet = await initializeWallet();
const capability = getWalletOriginCapabilities(wallet);
```

Copied or forged objects are rejected. Keep the initialized module and its
capability private to the wallet origin.

## Aligned operations

```ts
import initializeWallet from 'hd-wallet-wasm';
import type { AlignedAPI } from 'hd-wallet-wasm/aligned';

const wallet = await initializeWallet();
const aligned: AlignedAPI = wallet.aligned;
```

The initialized high-level module also exposes its aligned API. Refer to the
shipped TypeScript declarations for the complete batch surface.

## Canonical attestations

```js
import {
  buildCanonicalPayload,
  signEPMContent,
  verifyEPMSignature,
} from 'hd-wallet-wasm/attestation';

const canonicalPayload = buildCanonicalPayload({
  xpub,
  signingPubKeyHex,
  encryptionPubKeyHex,
  issuedAt: Math.floor(Date.now() / 1000),
});

const result = signEPMContent(wallet, epm, privateKey, {
  curve: 'ed25519',
});
const valid = verifyEPMSignature(wallet, epm, publicKey, {
  curve: 'ed25519',
});
```

The dedicated attestation subpath and root package expose the same declaration
surface for these helpers.

## Low-level module

Consumers that intentionally need the raw Emscripten API may initialize it
directly:

```js
import initializeRawModule from 'hd-wallet-wasm/wasm';

const raw = await initializeRawModule();
```

Prefer the root package for normal wallet work. Its wrapper owns module
construction, typed APIs, and wallet-origin capability binding.

## WASI artifact

`hd-wallet-wasm/wasi.wasm` and
`hd-wallet-wasm/dist/hd-wallet-wasi.wasm` resolve to the same file. Select the
name required by the host runtime, and validate the installed artifact before
executing it. The package includes only the canonical release binary.

## Security

- Supply entropy only from the platform cryptographic random source.
- Keep credential and private-key operations inside a trusted origin or process.
- Clear mutable secret buffers and call key `wipe()` methods after use.
- Pin a reviewed package version and preserve integrity metadata when self-hosting.
- Do not load executable wallet artifacts from third-party CDNs.

## Verification

The repository release lane stages an exact runtime inventory, validates the
WebAssembly header, packs the package with scripts disabled, installs it into a
clean external project, resolves every export inside that installation, and
type-checks representative NodeNext usage.

## License

Apache-2.0. See `LICENSE`.
