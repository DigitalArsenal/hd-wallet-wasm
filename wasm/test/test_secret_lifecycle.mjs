import assert from 'node:assert/strict';
import test from 'node:test';

import { createSdnTypedCapabilities } from '../src/sdn-typed.mjs';

const encoder = new TextEncoder();
const MAX_OUTPUT = 131072;
const VALID_HANDLE = (1n << 32n) | 1n;
const validIdentity = {
  schemaVersion: 1,
  identityScheme: 'sdn-bip32-slip10-purpose-v1',
  seedProfile: 'password-scrypt-v2',
  accountIndex: 0,
  accountLabel: null,
  accountXpub: 'xpub-fixture',
  accountPeerId: 'peer-fixture',
  accountFingerprint: '00112233',
  keys: [
    {
      purpose: 'asset-review-approval',
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      seedProfile: 'password-scrypt-v2',
      signatureProfile: 'ed25519-over-sha256-jcs-v1',
      curve: 'ed25519',
      derivation: 'slip10',
      path: "m/44'/0'/0'/2'/0'",
      encoding: 'raw',
      publicKeyHex: '11'.repeat(32),
      bip32Fingerprint: null,
      keyId: `sha256:${'22'.repeat(32)}`,
    },
    {
      purpose: 'contact-encryption',
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      seedProfile: 'password-scrypt-v2',
      signatureProfile: null,
      curve: 'x25519',
      derivation: 'slip10',
      path: "m/44'/0'/0'/1'/0'",
      encoding: 'raw',
      publicKeyHex: '33'.repeat(32),
      bip32Fingerprint: null,
      keyId: `sha256:${'44'.repeat(32)}`,
    },
    {
      purpose: 'sdn-authentication',
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      seedProfile: 'password-scrypt-v2',
      signatureProfile: 'ed25519-over-sha256-jcs-v1',
      curve: 'ed25519',
      derivation: 'slip10',
      path: "m/44'/0'/0'/0'/0'",
      encoding: 'raw',
      publicKeyHex: '55'.repeat(32),
      bip32Fingerprint: null,
      keyId: `sha256:${'66'.repeat(32)}`,
    },
  ],
};

function legacyIdentity(identityScheme, seedProfile) {
  return {
    ...validIdentity,
    identityScheme,
    seedProfile,
    keys: [{
      purpose: 'sdn-authentication',
      identityScheme,
      seedProfile,
      signatureProfile: 'ed25519-raw-32-v1',
      curve: 'ed25519',
      derivation: 'bip32-scalar-as-ed25519-seed',
      path: "m/44'/0'/0'/0/0",
      encoding: 'raw',
      publicKeyHex: '77'.repeat(32),
      bip32Fingerprint: null,
      keyId: `sha256:${'88'.repeat(32)}`,
    }],
  };
}

const legacyFastIdentity = legacyIdentity(
  'sdn-fast-password-auth-v1-legacy',
  'password-fast-v1-legacy',
);
const legacyMnemonicIdentity = legacyIdentity(
  'sdn-bip39-auth-v1-legacy',
  'bip39-mnemonic-v1-legacy',
);
const rawSignature = {
  schemaVersion: 1,
  keyId: legacyFastIdentity.keys[0].keyId,
  identityScheme: legacyFastIdentity.identityScheme,
  algorithm: 'ed25519',
  encoding: 'raw',
  signatureProfile: 'ed25519-raw-32-v1',
  signatureHex: '99'.repeat(64),
};
const canonicalSignature = {
  schemaVersion: 1,
  keyId: validIdentity.keys[2].keyId,
  identityScheme: validIdentity.identityScheme,
  algorithm: 'ed25519',
  encoding: 'raw',
  signatureProfile: 'ed25519-over-sha256-jcs-v1',
  canonicalEnvelope: '{"fixture":true}',
  signedDigestSha256: 'aa'.repeat(32),
  signatureHex: 'bb'.repeat(64),
};

const modernAccountOneIdentity = {
  ...validIdentity,
  accountIndex: 1,
  keys: validIdentity.keys.map((descriptor) => ({
    ...descriptor,
    path: descriptor.path.replace("m/44'/0'/0'/", "m/44'/0'/1'/"),
  })),
};

function makeFake(options = {}) {
  const memory = new ArrayBuffer(1024 * 1024);
  const HEAPU8 = new Uint8Array(memory);
  const view = new DataView(memory);
  let next = 16;
  let allocationAttempt = 0;
  const state = {
    allocations: [],
    frees: [],
    rawCalls: 0,
    destroyed: [],
    secretPointers: [],
    rawFinished: false,
  };
  if (options.failSecretWipeAfterRaw) {
    const fill = HEAPU8.fill.bind(HEAPU8);
    HEAPU8.fill = (...args) => {
      if (state.rawFinished) throw new Error('fixture wipe failure');
      return fill(...args);
    };
  }

  const writeJson = (value, outJson, outCapacity, outRequired) => {
    const bytes = encoder.encode(JSON.stringify(value));
    const required = options.required ?? bytes.length;
    view.setUint32(outRequired, required >>> 0, true);
    HEAPU8.set(bytes.subarray(0, Math.min(bytes.length, outCapacity)), outJson);
  };
  const writeIdentity = (
    outHandle,
    outJson,
    outCapacity,
    outRequired,
    identity = options.identity ?? validIdentity,
  ) => {
    const bytes = encoder.encode(JSON.stringify(identity));
    const required = options.required ?? bytes.length;
    const handle = options.handle ?? VALID_HANDLE;
    view.setBigUint64(outHandle, handle, true);
    view.setUint32(outRequired, required >>> 0, true);
    HEAPU8.set(bytes.subarray(0, Math.min(bytes.length, outCapacity)), outJson);
  };

  const wasm = {
    HEAPU8,
    _malloc(size) {
      allocationAttempt += 1;
      if (options.failAllocationAt === allocationAttempt) return 0;
      const aligned = (next + 7) & ~7;
      next = aligned + size;
      if (next > HEAPU8.length) return 0;
      state.allocations.push({ ptr: aligned, size });
      return aligned;
    },
    _free(ptr) {
      const allocation = state.allocations.find((candidate) => candidate.ptr === ptr);
      state.frees.push({
        ptr,
        bytes: allocation ? [...HEAPU8.slice(ptr, ptr + allocation.size)] : [],
      });
      if (options.failFree) throw new Error('fixture free failure');
    },
    _hd_sdn_derive_password_identity(...args) {
      state.rawCalls += 1;
      const [, , passwordPtr, passwordLength, , outHandle, outJson, outCapacity, outRequired] = args;
      state.secretPointers.push({ ptr: passwordPtr, size: passwordLength });
      if (options.partialBytes) HEAPU8.set(options.partialBytes, outJson);
      if ((options.status ?? 0) === 0) writeIdentity(outHandle, outJson, outCapacity, outRequired);
      else {
        if (options.handle !== undefined) view.setBigUint64(outHandle, options.handle, true);
        if (options.required !== undefined) view.setUint32(outRequired, options.required >>> 0, true);
      }
      state.rawFinished = true;
      if (options.throwAfterHandleWrite) throw new Error('fixture raw throw');
      if (options.afterRaw) options.afterRaw();
      return options.status ?? 0;
    },
    _hd_sdn_derive_legacy_password_identity(...args) {
      state.rawCalls += 1;
      const [, , passwordPtr, passwordLength, , outHandle, outJson, outCapacity, outRequired] = args;
      state.secretPointers.push({ ptr: passwordPtr, size: passwordLength });
      if ((options.status ?? 0) === 0) {
        writeIdentity(
          outHandle,
          outJson,
          outCapacity,
          outRequired,
          options.legacyFastIdentity ?? legacyFastIdentity,
        );
      }
      state.rawFinished = true;
      return options.status ?? 0;
    },
    _hd_sdn_import_legacy_mnemonic_identity(
      _mnemonic, _mnemonicLength, _account, outHandle, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      writeIdentity(
        outHandle,
        outJson,
        outCapacity,
        outRequired,
        options.legacyMnemonicIdentity ?? legacyMnemonicIdentity,
      );
      return options.status ?? 0;
    },
    _hd_sdn_import_remembered_identity(
      _ciphertext, _ciphertextLength, prfPtr, prfLength,
      _salt, _saltLength, _nonce, _nonceLength, _username, _usernameLength,
      _aad, _aadLength, outHandle, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      state.secretPointers.push({ ptr: prfPtr, size: prfLength });
      writeIdentity(outHandle, outJson, outCapacity, outRequired);
      return options.importStatus ?? 0;
    },
    _hd_sdn_sign_login_v1(
      _handle, _input, _length, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      writeJson(options.rawSignature ?? rawSignature, outJson, outCapacity, outRequired);
      return options.signStatus ?? 0;
    },
    _hd_sdn_sign_login_v2(
      _handle, _input, _length, _row, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      writeJson(options.canonicalSignature ?? canonicalSignature, outJson, outCapacity, outRequired);
      return options.signStatus ?? 0;
    },
    _hd_sdn_sign_asset_review_authority_activation(
      _handle, _input, _length, _row, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      writeJson(options.canonicalSignature ?? canonicalSignature, outJson, outCapacity, outRequired);
      return options.signStatus ?? 0;
    },
    _hd_sdn_sign_asset_review_decision(
      _handle, _input, _length, _row, outJson, outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      writeJson(options.canonicalSignature ?? canonicalSignature, outJson, outCapacity, outRequired);
      return options.signStatus ?? 0;
    },
    _hd_sdn_seal_remembered_identity(
      _handle, passwordPtr, passwordLength, prfPtr, prfLength,
      _salt, _saltLength, _nonce, _nonceLength, _aad, _aadLength,
      outBytes, _outCapacity, outRequired,
    ) {
      state.rawCalls += 1;
      state.secretPointers.push(
        { ptr: passwordPtr, size: passwordLength },
        { ptr: prfPtr, size: prfLength },
      );
      const sealed = Uint8Array.from({ length: 32 }, (_, index) => index);
      HEAPU8.set(sealed, outBytes);
      view.setUint32(outRequired, options.sealRequired ?? sealed.length, true);
      if (options.afterSealRaw) options.afterSealRaw();
      return options.sealStatus ?? 0;
    },
    _hd_sdn_destroy_identity(handle) {
      state.destroyed.push(handle);
      if (options.throwOnDestroy) throw new Error('fixture destroy failure');
    },
  };
  return { wasm, state };
}

function passwordInput() {
  return {
    usernameUtf8: encoder.encode('fixture-user'),
    passwordUtf8: encoder.encode('Fixture-Only-Password!'),
    accountIndex: 0,
  };
}

class HostileBytes extends Uint8Array {
  constructor(bytes) {
    super(bytes.length);
    Uint8Array.prototype.set.call(this, bytes);
    this.sliceDispatches = 0;
    this.fillDispatches = 0;
  }

  slice() {
    this.sliceDispatches += 1;
    throw new Error('caller-controlled slice must not run');
  }

  fill() {
    this.fillDispatches += 1;
    throw new Error('caller-controlled fill must not run');
  }
}

function assertHostileWiped(value) {
  assert.equal(value.sliceDispatches, 0);
  assert.equal(value.fillDispatches, 0);
  assert.deepEqual([...value], new Array(value.length).fill(0));
}

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) =>
    error?.name === 'SdnWalletError' && error.code === code);
}

test('all fourteen native errors and unknown status map without message parsing', async () => {
  const codes = [
    'INVALID_USERNAME', 'INVALID_PASSWORD', 'COMMON_PASSWORD', 'KDF_FAILURE',
    'INVALID_MNEMONIC', 'INVALID_ACCOUNT', 'STALE_HANDLE',
    'OPERATION_NOT_ALLOWED', 'INVALID_REQUEST', 'AUTHENTICATION_FAILED',
    'CAPACITY_EXCEEDED', 'CRYPTO_FAILURE', 'OUT_OF_MEMORY', 'FIPS_NOT_ALLOWED',
  ];
  for (let status = 1; status <= 14; status += 1) {
    const { wasm } = makeFake({ status });
    const sdn = createSdnTypedCapabilities(wasm);
    await expectCode(sdn.derivePasswordIdentity(passwordInput()), codes[status - 1]);
  }
  const { wasm } = makeFake({ status: 65535 });
  await expectCode(
    createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
    'CRYPTO_FAILURE',
  );
});

test('every sign and seal capability establishes handle authority before other validation', async () => {
  const { wasm, state } = makeFake();
  const sdn = createSdnTypedCapabilities(wasm);
  const forged = Object.freeze(Object.create(null));
  const throwingInput = new Proxy({}, {
    get() {
      throw new Error('fixture input getter must not run before handle validation');
    },
    ownKeys() {
      throw new Error('fixture input keys must not run before handle validation');
    },
  });
  const cases = [
    () => sdn.signSdnLoginV1(forged, new Uint8Array(1)),
    () => sdn.signSdnLoginV2(forged, { value: 1n }, 'wrong-row'),
    () => sdn.signAssetReviewAuthorityActivation(forged, {}, 'wrong-row'),
    () => sdn.signAssetReviewDecision(forged, {}, 'wrong-row'),
    () => sdn.sealRememberedIdentity(forged, {}),
    () => sdn.sealRememberedIdentity(forged, throwingInput),
  ];

  for (const invoke of cases) {
    await expectCode(Promise.resolve().then(invoke), 'STALE_HANDLE');
    assert.equal(state.rawCalls, 0);
  }
});

test('pre-authority cleanup failure preserves stale-handle precedence and wipes independent secrets', async () => {
  const target = makeFake();
  const targetSdn = createSdnTypedCapabilities(target.wasm);
  const foreign = makeFake();
  const foreignSdn = createSdnTypedCapabilities(foreign.wasm);
  const { handle: foreignHandle } = await foreignSdn.derivePasswordIdentity(passwordInput());

  for (const handle of [Object.freeze(Object.create(null)), foreignHandle]) {
    const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
    structuredClone(passwordUtf8.buffer, { transfer: [passwordUtf8.buffer] });
    const prfOutput = new Uint8Array(32).fill(7);
    assert.throws(() => targetSdn.sealRememberedIdentity(handle, {
      passwordUtf8,
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalAad: '{}',
    }), (error) => error?.name === 'SdnWalletError' && error.code === 'STALE_HANDLE');
    assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
    assert.equal(target.state.rawCalls, 0);
  }

  foreignSdn.destroySdnIdentity(foreignHandle);
});

test('KDF failure hides partial output and wipes caller and copied passwords', async () => {
  const rejected = encoder.encode('Fixture-Only-Rejected-Secret!');
  const { wasm, state } = makeFake({
    status: 4,
    partialBytes: encoder.encode('{"password":"Fixture-Only-Rejected-Secret!"}'),
  });
  const sdn = createSdnTypedCapabilities(wasm);
  const input = {
    usernameUtf8: encoder.encode('fixture-user'),
    passwordUtf8: rejected.slice(),
    accountIndex: 0,
  };
  let observed;
  try {
    await sdn.derivePasswordIdentity(input);
  } catch (error) {
    observed = error;
  }
  assert.equal(observed.code, 'KDF_FAILURE');
  assert.equal(JSON.stringify(observed).includes('Fixture-Only'), false);
  assert.deepEqual([...input.passwordUtf8], new Array(input.passwordUtf8.length).fill(0));
  for (const secret of state.secretPointers) {
    assert.deepEqual(
      [...wasm.HEAPU8.slice(secret.ptr, secret.ptr + secret.size)],
      new Array(secret.size).fill(0),
    );
  }
});

test('secret copy and wipe never dispatch caller-controlled typed-array methods', async () => {
  {
    const { wasm } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const passwordUtf8 = new HostileBytes(encoder.encode('Fixture-Only-Password!'));
    const result = await sdn.derivePasswordIdentity({
      usernameUtf8: encoder.encode('fixture-user'), passwordUtf8, accountIndex: 0,
    });
    assertHostileWiped(passwordUtf8);
    sdn.destroySdnIdentity(result.handle);
  }

  {
    const { wasm } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const passwordUtf8 = new HostileBytes(encoder.encode('Fixture-Only-Password!'));
    const result = await sdn.deriveLegacyPasswordIdentity({
      usernameUtf8: encoder.encode('fixture-user'), passwordUtf8, accountIndex: 0,
    });
    assertHostileWiped(passwordUtf8);
    sdn.destroySdnIdentity(result.handle);
  }

  {
    const { wasm } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const mnemonicUtf8 = new HostileBytes(
      encoder.encode('abandon '.repeat(11) + 'about'),
    );
    const result = await sdn.importLegacyMnemonicIdentity({ mnemonicUtf8, accountIndex: 0 });
    assertHostileWiped(mnemonicUtf8);
    sdn.destroySdnIdentity(result.handle);
  }

  {
    const { wasm } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const prfOutput = new HostileBytes(new Uint8Array(32).fill(7));
    const result = sdn.importRememberedIdentity({
      ciphertextAndTag: new Uint8Array(32),
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalUsernameUtf8: encoder.encode('fixture-user'),
      canonicalAad: '{}',
    });
    assertHostileWiped(prfOutput);
    sdn.destroySdnIdentity(result.handle);
  }

  {
    const { wasm } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const { handle } = await sdn.derivePasswordIdentity(passwordInput());
    const passwordUtf8 = new HostileBytes(encoder.encode('Fixture-Only-Password!'));
    const prfOutput = new HostileBytes(new Uint8Array(32).fill(9));
    const sealed = sdn.sealRememberedIdentity(handle, {
      passwordUtf8,
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalAad: '{}',
    });
    assert.equal(sealed.length, 32);
    assertHostileWiped(passwordUtf8);
    assertHostileWiped(prfOutput);
    sdn.destroySdnIdentity(handle);
  }

  {
    const { wasm, state } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const forged = Object.freeze(Object.create(null));
    const passwordUtf8 = new HostileBytes(encoder.encode('Fixture-Only-Password!'));
    const prfOutput = new HostileBytes(new Uint8Array(32).fill(5));
    assert.throws(() => sdn.sealRememberedIdentity(forged, {
      passwordUtf8,
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalAad: '{}',
    }), (error) => error.code === 'STALE_HANDLE');
    assert.equal(state.rawCalls, 0);
    assertHostileWiped(passwordUtf8);
    assertHostileWiped(prfOutput);
  }
});

test('post-raw caller cleanup failure rolls a new handle back exactly once', async () => {
  const options = {};
  const { wasm, state } = makeFake(options);
  const sdn = createSdnTypedCapabilities(wasm);
  const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
  options.afterRaw = () => {
    structuredClone(passwordUtf8.buffer, { transfer: [passwordUtf8.buffer] });
  };

  await expectCode(sdn.derivePasswordIdentity({
    usernameUtf8: encoder.encode('fixture-user'), passwordUtf8, accountIndex: 0,
  }), 'CRYPTO_FAILURE');
  assert.equal(state.rawCalls, 1);
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);
  for (const secret of state.secretPointers) {
    const freed = state.frees.find(({ ptr }) => ptr === secret.ptr);
    assert.deepEqual(freed.bytes, new Array(secret.size).fill(0));
  }
});

test('seal cleanup failure publishes no output, attempts every wipe, and keeps authority controlled', async () => {
  const options = {};
  const { wasm, state } = makeFake(options);
  const sdn = createSdnTypedCapabilities(wasm);
  const { handle } = await sdn.derivePasswordIdentity(passwordInput());
  const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
  const prfOutput = new Uint8Array(32).fill(7);
  options.afterSealRaw = () => {
    structuredClone(passwordUtf8.buffer, { transfer: [passwordUtf8.buffer] });
  };

  await expectCode(Promise.resolve().then(() => sdn.sealRememberedIdentity(handle, {
    passwordUtf8,
    prfOutput,
    hkdfSalt: new Uint8Array(32),
    nonce: new Uint8Array(12),
    canonicalAad: '{}',
  })), 'CRYPTO_FAILURE');
  assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
  assert.deepEqual(state.destroyed, []);
  sdn.destroySdnIdentity(handle);
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);
});

test('allocation failure at every position makes no raw call and reverses cleanup', async () => {
  for (let failure = 1; failure <= 5; failure += 1) {
    const { wasm, state } = makeFake({ failAllocationAt: failure });
    const sdn = createSdnTypedCapabilities(wasm);
    const input = passwordInput();
    await expectCode(sdn.derivePasswordIdentity(input), 'OUT_OF_MEMORY');
    assert.equal(state.rawCalls, 0);
    assert.deepEqual([...input.passwordUtf8], new Array(input.passwordUtf8.length).fill(0));
    const allocated = state.allocations.map(({ ptr }) => ptr);
    assert.deepEqual(state.frees.map(({ ptr }) => ptr), allocated.reverse());
    assert.equal(state.allocations.some(({ ptr }) => ptr === 0), false);
    assert.deepEqual([...wasm.HEAPU8.slice(0, 8)], new Array(8).fill(0));
    if (failure > 2) {
      const passwordAllocation = state.allocations[1];
      const freedPassword = state.frees.find(({ ptr }) => ptr === passwordAllocation.ptr);
      assert.deepEqual(freedPassword.bytes, new Array(passwordAllocation.size).fill(0));
    }
  }
});

test('a successful malloc is freed when HEAP validation fails before the first write', async () => {
  const { wasm, state } = makeFake();
  Object.defineProperty(wasm, 'HEAPU8', {
    configurable: true,
    get() {
      throw new Error('fixture HEAP getter failure');
    },
  });
  const sdn = createSdnTypedCapabilities(wasm);
  const input = passwordInput();

  await expectCode(sdn.derivePasswordIdentity(input), 'OUT_OF_MEMORY');
  assert.equal(state.rawCalls, 0);
  assert.equal(state.allocations.length, 1);
  assert.deepEqual(state.frees.map(({ ptr }) => ptr), [state.allocations[0].ptr]);
  assert.deepEqual([...input.passwordUtf8], new Array(input.passwordUtf8.length).fill(0));
});

test('every wrapper allocation position fails before its raw capability call', async () => {
  const rememberedInput = () => ({
    ciphertextAndTag: new Uint8Array(32),
    prfOutput: new Uint8Array(32).fill(1),
    hkdfSalt: new Uint8Array(32),
    nonce: new Uint8Array(12),
    canonicalUsernameUtf8: encoder.encode('fixture-user'),
    canonicalAad: '{}',
  });
  const cases = [
    {
      name: 'derive modern', setup: 0, allocations: 5,
      invoke: (sdn) => sdn.derivePasswordIdentity(passwordInput()),
    },
    {
      name: 'derive legacy', setup: 0, allocations: 5,
      invoke: (sdn) => sdn.deriveLegacyPasswordIdentity(passwordInput()),
    },
    {
      name: 'import mnemonic', setup: 0, allocations: 4,
      invoke: (sdn) => sdn.importLegacyMnemonicIdentity({
        mnemonicUtf8: encoder.encode('abandon '.repeat(11) + 'about'),
        accountIndex: 0,
      }),
    },
    {
      name: 'import remembered', setup: 0, allocations: 9,
      invoke: (sdn) => sdn.importRememberedIdentity(rememberedInput()),
    },
    {
      name: 'sign raw', setup: 5, allocations: 3,
      invoke: (sdn, handle) => sdn.signSdnLoginV1(handle, new Uint8Array(32)),
    },
    {
      name: 'sign login v2', setup: 5, allocations: 3,
      invoke: (sdn, handle) => sdn.signSdnLoginV2(handle, {}, 'sdn-node-console-v2'),
    },
    {
      name: 'sign activation', setup: 5, allocations: 3,
      invoke: (sdn, handle) => sdn.signAssetReviewAuthorityActivation(
        handle, {}, 'asset-review-authority-activation-v1',
      ),
    },
    {
      name: 'sign decision', setup: 5, allocations: 3,
      invoke: (sdn, handle) => sdn.signAssetReviewDecision(
        handle, {}, 'asset-review-decision-v1',
      ),
    },
    {
      name: 'seal remembered', setup: 5, allocations: 7,
      invoke: (sdn, handle) => sdn.sealRememberedIdentity(handle, {
        passwordUtf8: encoder.encode('Fixture-Only-Password!'),
        prfOutput: new Uint8Array(32),
        hkdfSalt: new Uint8Array(32),
        nonce: new Uint8Array(12),
        canonicalAad: '{}',
      }),
    },
  ];

  for (const entry of cases) {
    for (let position = 1; position <= entry.allocations; position += 1) {
      const { wasm, state } = makeFake({
        failAllocationAt: entry.setup + position,
      });
      const sdn = createSdnTypedCapabilities(wasm);
      let handle;
      if (entry.setup !== 0) {
        ({ handle } = await sdn.derivePasswordIdentity(passwordInput()));
      }
      const rawCallsBefore = state.rawCalls;
      const allocationsBefore = state.allocations.length;
      const freesBefore = state.frees.length;
      await expectCode(
        Promise.resolve().then(() => entry.invoke(sdn, handle)),
        'OUT_OF_MEMORY',
      );
      assert.equal(state.rawCalls, rawCallsBefore, `${entry.name} position ${position}`);
      assert.deepEqual(
        state.frees.slice(freesBefore).map(({ ptr }) => ptr),
        state.allocations.slice(allocationsBefore).map(({ ptr }) => ptr).reverse(),
        `${entry.name} position ${position}`,
      );
    }
  }
});

test('malformed success metadata and identity JSON roll back a pending handle exactly once', async () => {
  const malformed = [
    { handle: 0n },
    { handle: 1n },
    { handle: 1n << 32n },
    { handle: (1n << 32n) | 17n },
    { required: 0 },
    { required: MAX_OUTPUT + 1 },
    { identity: { ...validIdentity, identityScheme: 'unknown' } },
    { identity: { ...validIdentity, keys: [{ ...validIdentity.keys[0], curve: 'x25519' }] } },
    {
      identity: {
        ...validIdentity,
        seedProfile: 'password-fast-v1-legacy',
      },
    },
    {
      identity: {
        ...validIdentity,
        keys: validIdentity.keys.map((descriptor, index) => index === 0
          ? { ...descriptor, identityScheme: 'sdn-fast-password-auth-v1-legacy' }
          : descriptor),
      },
    },
  ];
  for (const variant of malformed) {
    const { wasm, state } = makeFake(variant);
    await expectCode(
      createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
      'CRYPTO_FAILURE',
    );
    if ((variant.handle ?? VALID_HANDLE) === 0n) assert.deepEqual(state.destroyed, []);
    else assert.deepEqual(state.destroyed, [variant.handle ?? VALID_HANDLE]);
  }

  const { wasm, state } = makeFake({
    required: 1,
    partialBytes: Uint8Array.of(0x7b),
  });
  await expectCode(
    createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
    'CRYPTO_FAILURE',
  );
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);
});

test('sign and seal wrappers reject malformed success metadata without publishing results', async () => {
  const signCases = [
    {
      name: 'raw required zero',
      configure: (options) => { options.required = 0; },
      invoke: (sdn, handle) => sdn.signSdnLoginV1(handle, new Uint8Array(32)),
    },
    {
      name: 'raw required oversized',
      configure: (options) => { options.required = MAX_OUTPUT + 1; },
      invoke: (sdn, handle) => sdn.signSdnLoginV1(handle, new Uint8Array(32)),
    },
    {
      name: 'raw malformed DTO',
      configure: (options) => { options.rawSignature = { ...rawSignature, extra: true }; },
      invoke: (sdn, handle) => sdn.signSdnLoginV1(handle, new Uint8Array(32)),
    },
    {
      name: 'canonical required zero',
      configure: (options) => { options.required = 0; },
      invoke: (sdn, handle) => sdn.signSdnLoginV2(handle, {}, 'sdn-node-console-v2'),
    },
    {
      name: 'canonical required oversized',
      configure: (options) => { options.required = MAX_OUTPUT + 1; },
      invoke: (sdn, handle) => sdn.signSdnLoginV2(handle, {}, 'sdn-node-console-v2'),
    },
    {
      name: 'canonical malformed DTO',
      configure: (options) => {
        options.canonicalSignature = { ...canonicalSignature, identityScheme: 'unknown' };
      },
      invoke: (sdn, handle) => sdn.signSdnLoginV2(handle, {}, 'sdn-node-console-v2'),
    },
  ];

  for (const entry of signCases) {
    const options = {};
    const { wasm, state } = makeFake(options);
    const sdn = createSdnTypedCapabilities(wasm);
    const { handle } = await sdn.derivePasswordIdentity(passwordInput());
    entry.configure(options);
    const allocationsBefore = state.allocations.length;
    const freesBefore = state.frees.length;
    await expectCode(
      Promise.resolve().then(() => entry.invoke(sdn, handle)),
      'CRYPTO_FAILURE',
    );
    assert.deepEqual(
      state.frees.slice(freesBefore).map(({ ptr }) => ptr),
      state.allocations.slice(allocationsBefore).map(({ ptr }) => ptr).reverse(),
      entry.name,
    );
    sdn.destroySdnIdentity(handle);
  }

  for (const required of [0, 16, 1025, MAX_OUTPUT + 1]) {
    const options = {};
    const { wasm, state } = makeFake(options);
    const sdn = createSdnTypedCapabilities(wasm);
    const { handle } = await sdn.derivePasswordIdentity(passwordInput());
    options.sealRequired = required;
    const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
    const prfOutput = new Uint8Array(32).fill(7);
    const allocationsBefore = state.allocations.length;
    const freesBefore = state.frees.length;
    await expectCode(Promise.resolve().then(() => sdn.sealRememberedIdentity(handle, {
      passwordUtf8,
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalAad: '{}',
    })), 'CRYPTO_FAILURE');
    assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
    assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
    assert.deepEqual(
      state.frees.slice(freesBefore).map(({ ptr }) => ptr),
      state.allocations.slice(allocationsBefore).map(({ ptr }) => ptr).reverse(),
      `seal required ${required}`,
    );
    sdn.destroySdnIdentity(handle);
  }
});

test('factory-specific scheme/profile confusion is rejected and rolled back', async () => {
  const { wasm, state } = makeFake({ legacyFastIdentity: validIdentity });
  await expectCode(
    createSdnTypedCapabilities(wasm).deriveLegacyPasswordIdentity(passwordInput()),
    'CRYPTO_FAILURE',
  );
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);

  const wrongAccount = makeFake({ identity: modernAccountOneIdentity });
  await expectCode(
    createSdnTypedCapabilities(wrongAccount.wasm).derivePasswordIdentity(passwordInput()),
    'CRYPTO_FAILURE',
  );
  assert.deepEqual(wrongAccount.state.destroyed, [VALID_HANDLE]);
});

test('caller-owned secrets are wiped even when validation fails before allocation', async () => {
  const { wasm } = makeFake();
  const sdn = createSdnTypedCapabilities(wasm);
  const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
  await expectCode(sdn.derivePasswordIdentity({
    ...passwordInput(),
    passwordUtf8,
    unknown: true,
  }), 'INVALID_REQUEST');
  assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));

  const mnemonicUtf8 = encoder.encode('abandon '.repeat(11) + 'about');
  await expectCode(sdn.importLegacyMnemonicIdentity({
    mnemonicUtf8,
    accountIndex: 0,
    unknown: true,
  }), 'INVALID_REQUEST');
  assert.deepEqual([...mnemonicUtf8], new Array(mnemonicUtf8.length).fill(0));

  const prfOutput = new Uint8Array(32).fill(3);
  assert.throws(() => sdn.importRememberedIdentity({
    ...{
      ciphertextAndTag: new Uint8Array(32),
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalUsernameUtf8: encoder.encode('fixture-user'),
      canonicalAad: '\ud800',
    },
  }), (error) => error.code === 'INVALID_REQUEST');
  assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
});

test('legacy credential and remembered ciphertext transport bounds fail before raw calls', async () => {
  {
    const { wasm, state } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const passwordUtf8 = new Uint8Array(4096).fill(0x70);
    const result = await sdn.deriveLegacyPasswordIdentity({
      usernameUtf8: new Uint8Array(4096).fill(0x75),
      passwordUtf8,
      accountIndex: 0,
    });
    assert.equal(result.identity.identityScheme, 'sdn-fast-password-auth-v1-legacy');
    assert.equal(state.rawCalls, 1);
    assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
    sdn.destroySdnIdentity(result.handle);
  }

  for (const field of ['usernameUtf8', 'passwordUtf8']) {
    const { wasm, state } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const input = {
      usernameUtf8: encoder.encode('fixture-user'),
      passwordUtf8: encoder.encode('Fixture-Only-Password!'),
      accountIndex: 0,
    };
    input[field] = new Uint8Array(4097).fill(0x61);
    await expectCode(
      sdn.deriveLegacyPasswordIdentity(input),
      field === 'usernameUtf8' ? 'INVALID_USERNAME' : 'INVALID_PASSWORD',
    );
    assert.equal(state.rawCalls, 0);
    assert.deepEqual([...input.passwordUtf8], new Array(input.passwordUtf8.length).fill(0));
  }

  for (const ciphertextLength of [15, 1025]) {
    const { wasm, state } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const prfOutput = new Uint8Array(32).fill(9);
    assert.throws(() => sdn.importRememberedIdentity({
      ciphertextAndTag: new Uint8Array(ciphertextLength),
      prfOutput,
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalUsernameUtf8: encoder.encode('fixture-user'),
      canonicalAad: '{}',
    }), (error) => error.code === 'INVALID_REQUEST');
    assert.equal(state.rawCalls, 0);
    assert.deepEqual([...prfOutput], new Array(prfOutput.length).fill(0));
  }

  for (const ciphertextLength of [16, 1024]) {
    const { wasm, state } = makeFake();
    const sdn = createSdnTypedCapabilities(wasm);
    const result = sdn.importRememberedIdentity({
      ciphertextAndTag: new Uint8Array(ciphertextLength),
      prfOutput: new Uint8Array(32),
      hkdfSalt: new Uint8Array(32),
      nonce: new Uint8Array(12),
      canonicalUsernameUtf8: encoder.encode('fixture-user'),
      canonicalAad: '{}',
    });
    assert.equal(state.rawCalls, 1);
    sdn.destroySdnIdentity(result.handle);
  }
});

test('nonzero status carrying a pending handle rolls it back once', async () => {
  const { wasm, state } = makeFake({ status: 9, handle: VALID_HANDLE });
  await expectCode(
    createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
    'INVALID_REQUEST',
  );
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);
});

test('raw throw after writing a handle still rolls pending authority back once', async () => {
  const { wasm, state } = makeFake({ throwAfterHandleWrite: true });
  await expectCode(
    createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
    'CRYPTO_FAILURE',
  );
  assert.deepEqual(state.destroyed, [VALID_HANDLE]);
});

test('wipe or free cleanup failure cannot publish a successful handle', async () => {
  for (const failure of [
    { failSecretWipeAfterRaw: true },
    { failFree: true },
  ]) {
    const { wasm, state } = makeFake(failure);
    await expectCode(
      createSdnTypedCapabilities(wasm).derivePasswordIdentity(passwordInput()),
      'CRYPTO_FAILURE',
    );
    assert.deepEqual(state.destroyed, [VALID_HANDLE]);
  }
});

test('destroy revokes JS authority even when the raw destroy boundary throws', async () => {
  const { wasm, state } = makeFake({ throwOnDestroy: true });
  const sdn = createSdnTypedCapabilities(wasm);
  const { handle } = await sdn.derivePasswordIdentity(passwordInput());
  assert.throws(() => sdn.destroySdnIdentity(handle), (error) =>
    error.code === 'CRYPTO_FAILURE');
  const rawCallsAfterDestroy = state.rawCalls;
  assert.throws(() => sdn.signSdnLoginV1(handle, new Uint8Array(32)), (error) =>
    error.code === 'STALE_HANDLE');
  assert.equal(state.rawCalls, rawCallsAfterDestroy);
  sdn.destroySdnIdentity(handle);
});

test('remembered open/seal wipe caller-owned PRF and password buffers on every exit', async () => {
  const { wasm } = makeFake();
  const sdn = createSdnTypedCapabilities(wasm);
  const openPrf = new Uint8Array(32).fill(7);
  const restored = sdn.importRememberedIdentity({
    ciphertextAndTag: new Uint8Array(32).fill(1),
    prfOutput: openPrf,
    hkdfSalt: new Uint8Array(32).fill(2),
    nonce: new Uint8Array(12).fill(3),
    canonicalUsernameUtf8: encoder.encode('fixture-user'),
    canonicalAad: '{"fixture":true}',
  });
  assert.deepEqual([...openPrf], new Array(32).fill(0));

  const passwordUtf8 = encoder.encode('Fixture-Only-Password!');
  const sealPrf = new Uint8Array(32).fill(9);
  const sealed = sdn.sealRememberedIdentity(restored.handle, {
    passwordUtf8,
    prfOutput: sealPrf,
    hkdfSalt: new Uint8Array(32).fill(4),
    nonce: new Uint8Array(12).fill(5),
    canonicalAad: '{"fixture":true}',
  });
  assert.equal(sealed.length, 32);
  assert.deepEqual([...passwordUtf8], new Array(passwordUtf8.length).fill(0));
  assert.deepEqual([...sealPrf], new Array(32).fill(0));
  sdn.destroySdnIdentity(restored.handle);

  const failing = makeFake({ importStatus: 10 });
  const failingPrf = new Uint8Array(32).fill(6);
  assert.throws(() => createSdnTypedCapabilities(failing.wasm).importRememberedIdentity({
    ciphertextAndTag: new Uint8Array(32),
    prfOutput: failingPrf,
    hkdfSalt: new Uint8Array(32),
    nonce: new Uint8Array(12),
    canonicalUsernameUtf8: encoder.encode('fixture-user'),
    canonicalAad: '{"fixture":true}',
  }), (error) => error.code === 'AUTHENTICATION_FAILED');
  assert.deepEqual([...failingPrf], new Array(32).fill(0));
});

test('the real C ABI reports required capacity, publishes no handle, and wipes credentials', async () => {
  const { default: createRawModule } = await import('../dist/hd-wallet.js');
  const raw = await createRawModule();
  const exactRawEntrypoints = [
    '_hd_sdn_derive_password_identity',
    '_hd_sdn_derive_legacy_password_identity',
    '_hd_sdn_import_legacy_mnemonic_identity',
    '_hd_sdn_import_remembered_identity',
    '_hd_sdn_sign_login_v1',
    '_hd_sdn_sign_login_v2',
    '_hd_sdn_sign_asset_review_authority_activation',
    '_hd_sdn_sign_asset_review_decision',
    '_hd_sdn_seal_remembered_identity',
    '_hd_sdn_destroy_identity',
  ];
  assert.deepEqual(
    Object.keys(raw).filter((name) => /^_hd_sdn_/.test(name)).sort(),
    exactRawEntrypoints.sort(),
  );
  const allocations = [];
  const allocate = (bytes) => {
    const ptr = raw._malloc(Math.max(1, bytes.length));
    allocations.push(ptr);
    raw.HEAPU8.set(bytes, ptr);
    return ptr;
  };
  const username = encoder.encode('fixture-legacy-user');
  const password = encoder.encode('Fixture-Only-Legacy-Secret-0001!');
  const usernamePtr = allocate(username);
  const passwordPtr = allocate(password);
  const outHandle = allocate(new Uint8Array(8));
  const outJson = allocate(new Uint8Array(1));
  const outRequired = allocate(new Uint8Array(4));
  try {
    const status = raw._hd_sdn_derive_legacy_password_identity(
      usernamePtr, username.length, passwordPtr, password.length, 0,
      outHandle, outJson, 1, outRequired,
    );
    const view = new DataView(raw.HEAPU8.buffer);
    assert.equal(status, 9);
    assert.equal(view.getBigUint64(outHandle, true), 0n);
    assert.ok(view.getUint32(outRequired, true) > 1);
    assert.deepEqual(
      [...raw.HEAPU8.slice(passwordPtr, passwordPtr + password.length)],
      new Array(password.length).fill(0),
    );

    raw.HEAPU8.fill(0xff, outHandle, outHandle + 8);
    raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
    const invalidSecretStatus = raw._hd_sdn_derive_legacy_password_identity(
      usernamePtr, username.length, 0, 1, 0,
      outHandle, outJson, 1, outRequired,
    );
    assert.equal(invalidSecretStatus, 9);
    assert.equal(view.getBigUint64(outHandle, true), 0n);
    assert.equal(view.getUint32(outRequired, true), 0);

    const secondPasswordPtr = allocate(password);
    raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
    const invalidHandleOutputStatus = raw._hd_sdn_derive_legacy_password_identity(
      usernamePtr, username.length, secondPasswordPtr, password.length, 0,
      0, outJson, 1, outRequired,
    );
    assert.equal(invalidHandleOutputStatus, 9);
    assert.equal(view.getUint32(outRequired, true), 0);
    assert.deepEqual(
      [...raw.HEAPU8.slice(secondPasswordPtr, secondPasswordPtr + password.length)],
      new Array(password.length).fill(0),
    );

    const oversizedUsername = new Uint8Array(4097).fill(0x75);
    const oversizedUsernamePtr = allocate(oversizedUsername);
    const usernameBoundaryPasswordPtr = allocate(password);
    raw.HEAPU8.fill(0xff, outHandle, outHandle + 8);
    raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
    const oversizedUsernameStatus = raw._hd_sdn_derive_legacy_password_identity(
      oversizedUsernamePtr, oversizedUsername.length,
      usernameBoundaryPasswordPtr, password.length, 0,
      outHandle, outJson, 1, outRequired,
    );
    assert.equal(oversizedUsernameStatus, 1);
    assert.equal(view.getBigUint64(outHandle, true), 0n);
    assert.equal(view.getUint32(outRequired, true), 0);
    assert.deepEqual(
      [...raw.HEAPU8.slice(
        usernameBoundaryPasswordPtr,
        usernameBoundaryPasswordPtr + password.length,
      )],
      new Array(password.length).fill(0),
    );

    const oversizedPassword = new Uint8Array(4097).fill(0x70);
    const oversizedPasswordPtr = allocate(oversizedPassword);
    raw.HEAPU8.fill(0xff, outHandle, outHandle + 8);
    raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
    const oversizedPasswordStatus = raw._hd_sdn_derive_legacy_password_identity(
      usernamePtr, username.length, oversizedPasswordPtr, oversizedPassword.length, 0,
      outHandle, outJson, 1, outRequired,
    );
    assert.equal(oversizedPasswordStatus, 2);
    assert.equal(view.getBigUint64(outHandle, true), 0n);
    assert.equal(view.getUint32(outRequired, true), 0);
    assert.deepEqual(
      [...raw.HEAPU8.slice(oversizedPasswordPtr, oversizedPasswordPtr + oversizedPassword.length)],
      new Array(oversizedPassword.length).fill(0),
    );

    const sealPassword = encoder.encode('Fixture-Only-Password!');
    const sealPasswordPtr = allocate(sealPassword);
    const saltPtr = allocate(new Uint8Array(32));
    const noncePtr = allocate(new Uint8Array(12));
    const aadPtr = allocate(encoder.encode('{}'));

    for (const ciphertextLength of [15, 1025]) {
      const ciphertextPtr = allocate(new Uint8Array(ciphertextLength));
      const importPrfPtr = allocate(new Uint8Array(32).fill(0x44));
      raw.HEAPU8.fill(0xff, outHandle, outHandle + 8);
      raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
      const invalidCiphertextStatus = raw._hd_sdn_import_remembered_identity(
        ciphertextPtr, ciphertextLength,
        importPrfPtr, 32,
        saltPtr, 32,
        noncePtr, 12,
        usernamePtr, username.length,
        aadPtr, 2,
        outHandle, outJson, 1, outRequired,
      );
      assert.equal(invalidCiphertextStatus, 9);
      assert.equal(view.getBigUint64(outHandle, true), 0n);
      assert.equal(view.getUint32(outRequired, true), 0);
      assert.deepEqual(
        [...raw.HEAPU8.slice(importPrfPtr, importPrfPtr + 32)],
        new Array(32).fill(0),
      );
    }

    raw.HEAPU8.fill(0xff, outRequired, outRequired + 4);
    const invalidPrfStatus = raw._hd_sdn_seal_remembered_identity(
      0n,
      sealPasswordPtr, sealPassword.length,
      0, 32,
      saltPtr, 32,
      noncePtr, 12,
      aadPtr, 2,
      outJson, 1, outRequired,
    );
    assert.equal(invalidPrfStatus, 9);
    assert.equal(view.getUint32(outRequired, true), 0);
    assert.deepEqual(
      [...raw.HEAPU8.slice(sealPasswordPtr, sealPasswordPtr + sealPassword.length)],
      new Array(sealPassword.length).fill(0),
    );
  } finally {
    while (allocations.length) raw._free(allocations.pop());
  }
});
