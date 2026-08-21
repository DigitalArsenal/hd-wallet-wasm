import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import init from '../src/index.mjs';

const operations = JSON.parse(await readFile(
  new URL('../../test/fixtures/sdn-operation-wire-v1.json', import.meta.url),
  'utf8',
));
const vectors = JSON.parse(await readFile(
  new URL('../../test/fixtures/sdn-wallet-vectors.v1.json', import.meta.url),
  'utf8',
));
const encoder = new TextEncoder();

function decodeBase64url(value) {
  return Uint8Array.from(Buffer.from(value, 'base64url'));
}

function assertSdnError(fn, code) {
  assert.throws(fn, (error) => error?.name === 'SdnWalletError' && error.code === code);
}

function expectedRaw(row) {
  return {
    schemaVersion: 1,
    keyId: row.authenticationKeyId,
    identityScheme: row.identityScheme,
    algorithm: 'ed25519',
    encoding: 'raw',
    signatureProfile: row.signatureProfile,
    signatureHex: row.signatureHex,
  };
}

function expectedCanonical(row, keyId) {
  return {
    schemaVersion: 1,
    keyId,
    identityScheme: row.identityScheme,
    algorithm: 'ed25519',
    encoding: 'raw',
    signatureProfile: row.signatureProfile,
    canonicalEnvelope: row.canonicalEnvelope,
    signedDigestSha256: row.signedDigestSha256,
    signatureHex: row.signatureHex,
  };
}

test('legacy password and mnemonic accounts reproduce the complete raw-v1 signature matrix', async () => {
  const wallet = await init();
  for (const vector of vectors.legacyIdentities) {
    for (const account of vector.accounts) {
      const row = operations.authenticationCases.find((candidate) =>
        candidate.identityScheme === vector.identityScheme &&
        candidate.accountIndex === account.index);
      let result;
      if (vector.source.kind === 'password') {
        result = await wallet.sdn.deriveLegacyPasswordIdentity({
          usernameUtf8: encoder.encode(vector.source.rawUsername),
          passwordUtf8: encoder.encode(vector.source.password),
          accountIndex: account.index,
        });
      } else {
        result = await wallet.sdn.importLegacyMnemonicIdentity({
          mnemonicUtf8: encoder.encode(vector.source.mnemonic),
          accountIndex: account.index,
        });
      }
      const signature = wallet.sdn.signSdnLoginV1(
        result.handle,
        decodeBase64url(row.request.challengeBase64url),
      );
      assert.deepEqual(signature, expectedRaw(row));
      assert.equal(Object.isFrozen(signature), true);

      assertSdnError(() => wallet.sdn.signSdnLoginV2(
        result.handle,
        operations.authenticationCases.find((candidate) =>
          candidate.operation === 'sdn.auth.jcs-envelope.v2').request,
        'sdn-node-console-v2',
      ), 'OPERATION_NOT_ALLOWED');
      assertSdnError(() => wallet.sdn.signAssetReviewAuthorityActivation(
        result.handle,
        operations.authorityActivationCases[0].request,
        'asset-review-authority-activation-v1',
      ), 'OPERATION_NOT_ALLOWED');
      assertSdnError(() => wallet.sdn.signAssetReviewDecision(
        result.handle,
        operations.decisionCases[0].request,
        'asset-review-decision-v1',
      ), 'OPERATION_NOT_ALLOWED');
      wallet.sdn.destroySdnIdentity(result.handle);
    }
  }
});
test('password-scrypt-v2 reproduces v2 login, activation, and decision fixtures only', async () => {
  const wallet = await init();
  const source = vectors.newIdentity.passwordVectors[0];
  const handles = new Map();

  for (const account of vectors.newIdentity.accounts) {
    handles.set(account.index, await wallet.sdn.derivePasswordIdentity({
      usernameUtf8: encoder.encode(source.rawUsername),
      passwordUtf8: encoder.encode(source.password),
      accountIndex: account.index,
    }));
  }

  for (const row of operations.authenticationCases.filter((candidate) =>
    candidate.operation === 'sdn.auth.jcs-envelope.v2')) {
    const result = handles.get(row.accountIndex);
    assert.deepEqual(
      wallet.sdn.signSdnLoginV2(result.handle, row.request, 'sdn-node-console-v2'),
      expectedCanonical(row, row.authenticationKeyId),
    );
    assertSdnError(() => wallet.sdn.signSdnLoginV1(
      result.handle,
      decodeBase64url(row.request.challengeBase64url),
    ), 'OPERATION_NOT_ALLOWED');
  }

  const accountZero = handles.get(0);
  for (const row of operations.authorityActivationCases) {
    assert.deepEqual(
      wallet.sdn.signAssetReviewAuthorityActivation(
        accountZero.handle,
        row.request,
        'asset-review-authority-activation-v1',
      ),
      expectedCanonical(row, row.approvalKeyId),
    );
  }
  for (const row of operations.decisionCases) {
    assert.deepEqual(
      wallet.sdn.signAssetReviewDecision(
        accountZero.handle,
        row.request,
        'asset-review-decision-v1',
      ),
      expectedCanonical(row, row.approvalKeyId),
    );
  }

  assertSdnError(() => wallet.sdn.signSdnLoginV2(
    accountZero.handle,
    operations.authenticationCases.find((row) =>
      row.operation === 'sdn.auth.jcs-envelope.v2').request,
    'asset-review-decision-v1',
  ), 'INVALID_REQUEST');

  for (const result of handles.values()) wallet.sdn.destroySdnIdentity(result.handle);
});

test('typed request adapters reject missing, unknown, relabeled, and malformed fields', async () => {
  const wallet = await init();
  const source = vectors.newIdentity.passwordVectors[0];
  const { handle } = await wallet.sdn.derivePasswordIdentity({
    usernameUtf8: encoder.encode(source.rawUsername),
    passwordUtf8: encoder.encode(source.password),
    accountIndex: 0,
  });
  const login = operations.authenticationCases.find((row) =>
    row.operation === 'sdn.auth.jcs-envelope.v2').request;
  const activation = operations.authorityActivationCases[0].request;
  const approval = operations.decisionCases[0].request;

  assertSdnError(() => wallet.sdn.signSdnLoginV2(
    handle,
    { ...login, unknown: true },
    'sdn-node-console-v2',
  ), 'INVALID_REQUEST');
  const { nonce: _nonce, ...missingNonce } = login;
  assertSdnError(() => wallet.sdn.signSdnLoginV2(
    handle,
    missingNonce,
    'sdn-node-console-v2',
  ), 'INVALID_REQUEST');
  assertSdnError(() => wallet.sdn.signAssetReviewAuthorityActivation(
    handle,
    { ...activation, signatureProfile: 'ed25519-raw-32-v1' },
    'asset-review-authority-activation-v1',
  ), 'INVALID_REQUEST');
  assertSdnError(() => wallet.sdn.signAssetReviewDecision(
    handle,
    { ...approval, reviewedTransform: { ...approval.reviewedTransform, scale: [1, 0, 1] } },
    'asset-review-decision-v1',
  ), 'INVALID_REQUEST');
  wallet.sdn.destroySdnIdentity(handle);
});
