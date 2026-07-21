import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import init, { createHDWallet } from '../src/index.mjs';
import * as hdWalletModule from '../src/index.mjs';

const vectors = JSON.parse(await readFile(
  new URL('../../test/fixtures/sdn-wallet-vectors.v1.json', import.meta.url),
  'utf8',
));
const encoder = new TextEncoder();

const CAPABILITY_METHODS = [
  'derivePasswordIdentity',
  'deriveLegacyPasswordIdentity',
  'importLegacyMnemonicIdentity',
  'importRememberedIdentity',
  'signSdnLoginV1',
  'signSdnLoginV2',
  'signAssetReviewAuthorityActivation',
  'signAssetReviewDecision',
  'sealRememberedIdentity',
  'destroySdnIdentity',
];

function modernExpected(account) {
  const scheme = vectors.newIdentity.identityScheme;
  const profile = vectors.newIdentity.seedProfile;
  return {
    schemaVersion: 1,
    identityScheme: scheme,
    seedProfile: profile,
    accountIndex: account.index,
    accountLabel: null,
    accountXpub: account.accountXpub,
    accountPeerId: account.peerId,
    accountFingerprint: account.fingerprint,
    keys: [
      {
        purpose: 'asset-review-approval',
        identityScheme: scheme,
        seedProfile: profile,
        signatureProfile: 'ed25519-over-sha256-jcs-v1',
        curve: 'ed25519',
        derivation: 'slip10',
        path: account.assetReviewApproval.path,
        encoding: 'raw',
        publicKeyHex: account.assetReviewApproval.publicKeyHex,
        bip32Fingerprint: null,
        keyId: account.assetReviewApproval.keyId,
      },
      {
        purpose: 'contact-encryption',
        identityScheme: scheme,
        seedProfile: profile,
        signatureProfile: null,
        curve: 'x25519',
        derivation: 'slip10',
        path: account.contactEncryption.path,
        encoding: 'raw',
        publicKeyHex: account.contactEncryption.publicKeyHex,
        bip32Fingerprint: null,
        keyId: `sha256:${account.contactEncryption.publicKeyHex}`.replace(
          account.contactEncryption.publicKeyHex,
          // The key ID is deliberately sourced from the returned native DTO;
          // native vector assertions independently freeze its SHA-256 value.
          '__native_contact_key_id__',
        ),
      },
      {
        purpose: 'sdn-authentication',
        identityScheme: scheme,
        seedProfile: profile,
        signatureProfile: 'ed25519-over-sha256-jcs-v1',
        curve: 'ed25519',
        derivation: 'slip10',
        path: account.authentication.path,
        encoding: 'raw',
        publicKeyHex: account.authentication.publicKeyHex,
        bip32Fingerprint: null,
        keyId: account.authentication.keyId,
      },
    ],
  };
}

function legacyExpected(vector, account) {
  return {
    schemaVersion: 1,
    identityScheme: vector.identityScheme,
    seedProfile: vector.seedProfile,
    accountIndex: account.index,
    accountLabel: null,
    accountXpub: vector.rootPublicIdentity.accountXpub,
    accountPeerId: vector.rootPublicIdentity.peerId,
    accountFingerprint: vector.rootPublicIdentity.fingerprint,
    keys: [{
      purpose: 'sdn-authentication',
      identityScheme: vector.identityScheme,
      seedProfile: vector.seedProfile,
      signatureProfile: 'ed25519-raw-32-v1',
      curve: 'ed25519',
      derivation: 'bip32-scalar-as-ed25519-seed',
      path: account.authentication.path,
      encoding: 'raw',
      publicKeyHex: account.authentication.publicKeyHex,
      bip32Fingerprint: null,
      keyId: account.authentication.keyId,
    }],
  };
}

function assertDeepFrozen(value) {
  assert.equal(Object.isFrozen(value), true);
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) {
      if (child && typeof child === 'object') assertDeepFrozen(child);
    }
  }
}

function assertSdnError(fn, code) {
  assert.throws(fn, (error) => error?.name === 'SdnWalletError' && error.code === code);
}

test('init and createHDWallet attach one exact immutable capability object', async () => {
  for (const factory of [init, createHDWallet]) {
    const wallet = await factory();
    assert.deepEqual(Object.keys(wallet.sdn).sort(), [...CAPABILITY_METHODS].sort());
    for (const method of CAPABILITY_METHODS) {
      assert.equal(typeof wallet.sdn[method], 'function', method);
    }
    assert.equal(Object.isFrozen(wallet.sdn), true);
    const descriptor = Object.getOwnPropertyDescriptor(wallet, 'sdn');
    assert.equal(descriptor.enumerable, true);
    assert.equal(descriptor.writable, false);
    assert.equal(descriptor.configurable, false);
    assert.throws(() => { wallet.sdn = null; }, TypeError);
    assert.throws(() => Object.defineProperty(wallet, 'sdn', { value: null }), TypeError);
    for (const forbidden of [
      'describeSdnIdentity', 'sign', 'signBytes', 'getPrivateKey',
      'seed', 'seedBytes', 'exportSeed',
    ]) {
      assert.equal(Object.hasOwn(wallet.sdn, forbidden), false, forbidden);
      assert.equal(Object.hasOwn(wallet, forbidden), false, forbidden);
    }
  }
});

test('wallet-origin capabilities are immutable, module-authentic, and resolver-only', async () => {
  assert.equal(typeof hdWalletModule.getWalletOriginCapabilities, 'function');

  const first = await init();
  const second = await createHDWallet();
  const firstBinding = first.walletOriginCapabilities;
  const secondBinding = second.walletOriginCapabilities;

  assert.notEqual(firstBinding, secondBinding);
  for (const [wallet, binding] of [
    [first, firstBinding],
    [second, secondBinding],
  ]) {
    assert.deepEqual(Object.keys(binding).sort(), ['sdn', 'sha256']);
    assert.equal(Object.isFrozen(binding), true);
    assert.equal(binding.sdn, wallet.sdn);
    assert.equal(typeof binding.sha256, 'function');
    assert.equal(hdWalletModule.getWalletOriginCapabilities(wallet), binding);

    const descriptor = Object.getOwnPropertyDescriptor(
      wallet,
      'walletOriginCapabilities',
    );
    assert.deepEqual(descriptor, {
      value: binding,
      enumerable: false,
      writable: false,
      configurable: false,
    });
    assert.equal(Object.keys(wallet).includes('walletOriginCapabilities'), false);
    assert.throws(() => { wallet.walletOriginCapabilities = null; }, TypeError);
    assert.throws(() => Object.defineProperty(wallet, 'walletOriginCapabilities', {
      value: null,
    }), TypeError);
  }

  const input = Uint8Array.of(1, 2, 3, 4);
  const expected = first.utils.sha256(input);
  const originalSha256 = first.utils.sha256;
  first.utils.sha256 = () => new Uint8Array(32).fill(0xff);
  try {
    assert.deepEqual(firstBinding.sha256(input), expected);
  } finally {
    first.utils.sha256 = originalSha256;
  }

  const forgedPair = Object.create(null);
  Object.defineProperty(forgedPair, 'walletOriginCapabilities', {
    value: Object.freeze({ sdn: first.sdn, sha256: secondBinding.sha256 }),
    enumerable: false,
    writable: false,
    configurable: false,
  });
  const copiedBinding = Object.create(null);
  Object.defineProperty(copiedBinding, 'walletOriginCapabilities', {
    value: firstBinding,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  const inheritedBinding = Object.create(first);

  for (const candidate of [
    null,
    {},
    forgedPair,
    copiedBinding,
    inheritedBinding,
  ]) {
    assert.throws(
      () => hdWalletModule.getWalletOriginCapabilities(candidate),
      TypeError,
    );
  }

  for (const forbidden of [
    'createWalletOriginCapabilities',
    'registerWalletOriginCapabilities',
    'setWalletOriginCapabilities',
  ]) {
    assert.equal(Object.hasOwn(hdWalletModule, forbidden), false, forbidden);
  }
});

test('password-scrypt-v2 reproduces both native account identities and wipes passwords', async () => {
  const wallet = await init();
  const source = vectors.newIdentity.passwordVectors[0];

  for (const account of vectors.newIdentity.accounts) {
    const usernameUtf8 = encoder.encode(source.rawUsername);
    const passwordUtf8 = encoder.encode(source.password);
    const pending = wallet.sdn.derivePasswordIdentity({
      usernameUtf8,
      passwordUtf8,
      accountIndex: account.index,
    });
    assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
    usernameUtf8.fill(0x7f);

    const result = await pending;
    const expected = modernExpected(account);
    const contact = result.identity.keys.find((key) => key.purpose === 'contact-encryption');
    expected.keys[1].keyId = contact.keyId;
    assert.match(contact.keyId, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(result.identity, expected);
    assertDeepFrozen(result.identity);
    assert.equal(Object.getPrototypeOf(result.handle), null);
    assert.equal(Object.isFrozen(result.handle), true);
    assert.deepEqual(Reflect.ownKeys(result.handle), []);
    if (account.index === 1) {
      const sealPassword = encoder.encode(source.password);
      const sealPrf = new Uint8Array(32).fill(0x11);
      assertSdnError(() => wallet.sdn.sealRememberedIdentity(result.handle, {
        passwordUtf8: sealPassword,
        prfOutput: sealPrf,
        hkdfSalt: new Uint8Array(32).fill(0x22),
        nonce: new Uint8Array(12).fill(0x33),
        canonicalAad: '{}',
      }), 'OPERATION_NOT_ALLOWED');
      assert.deepEqual([...sealPassword], new Array(sealPassword.length).fill(0));
      assert.deepEqual([...sealPrf], new Array(sealPrf.length).fill(0));
    }
    wallet.sdn.destroySdnIdentity(result.handle);
  }
});

test('both legacy factories reproduce account 0/1 and omit approval/contact descriptors', async () => {
  const wallet = await init();

  for (const vector of vectors.legacyIdentities) {
    for (const account of vector.accounts) {
      let result;
      if (vector.source.kind === 'password') {
        const usernameUtf8 = encoder.encode(vector.source.rawUsername);
        const passwordUtf8 = encoder.encode(vector.source.password);
        result = await wallet.sdn.deriveLegacyPasswordIdentity({
          usernameUtf8,
          passwordUtf8,
          accountIndex: account.index,
        });
        assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
      } else {
        const mnemonicUtf8 = encoder.encode(vector.source.mnemonic);
        result = await wallet.sdn.importLegacyMnemonicIdentity({
          mnemonicUtf8,
          accountIndex: account.index,
        });
        assert.deepEqual([...mnemonicUtf8], new Array(mnemonicUtf8.length).fill(0));
      }
      assert.deepEqual(result.identity, legacyExpected(vector, account));
      assert.equal(result.identity.keys.length, 1);
      wallet.sdn.destroySdnIdentity(result.handle);
    }
  }
});

test('legacy password migration accepts the frozen 4096-byte credential boundary', async () => {
  const wallet = await init();
  const passwordUtf8 = new Uint8Array(4096).fill(0x70);
  const result = await wallet.sdn.deriveLegacyPasswordIdentity({
    usernameUtf8: new Uint8Array(4096).fill(0x75),
    passwordUtf8,
    accountIndex: 0,
  });
  assert.equal(result.identity.identityScheme, 'sdn-fast-password-auth-v1-legacy');
  assert.equal(result.identity.seedProfile, 'password-fast-v1-legacy');
  assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
  wallet.sdn.destroySdnIdentity(result.handle);
});

test('opaque handles reject foreign, forged, cloned, spread, and proxied authority', async () => {
  const legacy = vectors.legacyIdentities[0];
  const firstWallet = await init();
  const secondWallet = await init();
  const input = () => ({
    usernameUtf8: encoder.encode(legacy.source.rawUsername),
    passwordUtf8: encoder.encode(legacy.source.password),
    accountIndex: 0,
  });
  const first = await firstWallet.sdn.deriveLegacyPasswordIdentity(input());
  const second = await secondWallet.sdn.deriveLegacyPasswordIdentity(input());
  const challenge = Uint8Array.from({ length: 32 }, (_, index) => index);

  for (const candidate of [
    second.handle,
    Object.create(null),
    { ...first.handle },
    new Proxy(first.handle, {}),
    structuredClone(first.handle),
  ]) {
    assertSdnError(() => firstWallet.sdn.signSdnLoginV1(candidate, challenge), 'STALE_HANDLE');
  }
  assertSdnError(() => secondWallet.sdn.signSdnLoginV1(first.handle, challenge), 'STALE_HANDLE');

  assert.equal(firstWallet.sdn.signSdnLoginV1(first.handle, challenge).schemaVersion, 1);
  assert.equal(secondWallet.sdn.signSdnLoginV1(second.handle, challenge).schemaVersion, 1);
  firstWallet.sdn.destroySdnIdentity(first.handle);
  firstWallet.sdn.destroySdnIdentity(first.handle);
  assertSdnError(() => firstWallet.sdn.signSdnLoginV1(first.handle, challenge), 'STALE_HANDLE');
  assertSdnError(() => firstWallet.sdn.signSdnLoginV2(
    first.handle, {}, 'sdn-node-console-v2',
  ), 'STALE_HANDLE');
  assertSdnError(() => firstWallet.sdn.signAssetReviewAuthorityActivation(
    first.handle, {}, 'asset-review-authority-activation-v1',
  ), 'STALE_HANDLE');
  assertSdnError(() => firstWallet.sdn.signAssetReviewDecision(
    first.handle, {}, 'asset-review-decision-v1',
  ), 'STALE_HANDLE');
  const passwordUtf8 = encoder.encode('Fixture-Only-Legacy-Secret-0001!');
  const prfOutput = new Uint8Array(32).fill(9);
  assertSdnError(() => firstWallet.sdn.sealRememberedIdentity(first.handle, {
    passwordUtf8,
    prfOutput,
    hkdfSalt: new Uint8Array(32),
    nonce: new Uint8Array(12),
    canonicalAad: '{}',
  }), 'STALE_HANDLE');
  assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
  assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
  secondWallet.sdn.destroySdnIdentity(second.handle);
});
