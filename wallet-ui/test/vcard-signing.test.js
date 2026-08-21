import { describe, expect, it } from 'vitest';

async function loadVCardSigning() {
  const signing = await import('../src/vcard-signing.js').catch(() => null);
  expect(signing?.createSignedVCardArtifacts).toBeTypeOf('function');
  expect(signing?.getVCardSignatureStatus).toBeTypeOf('function');
  expect(signing?.updateVCardSignatureBadge).toBeTypeOf('function');
  expect(signing?.withSelectedWalletSigningKey).toBeTypeOf('function');
  return signing;
}

function signingContext(overrides = {}) {
  return {
    hdRoot: {},
    wallet: { accountIndex: 7 },
    buildSigningPath: (coinType, account, index) => `m/${coinType}/${account}/${index}`,
    deriveHDKey: () => ({
      privateKey: () => new Uint8Array([1, 2, 3, 4]),
      wipe() {},
    }),
    ...overrides,
  };
}

const SIGNED_VCARD = [
  'BEGIN:VCARD',
  'VERSION:3.0',
  'FN:Ada Lovelace',
  'item1.X-ABLabel:Digital Signature #1',
  'item1.X-ABRELATEDNAMES:c2lnbmF0dXJl:501:7:0',
  'END:VCARD',
].join('\n');

const UNSIGNED_VCARD = [
  'BEGIN:VCARD',
  'VERSION:3.0',
  'FN:Ada Lovelace',
  'END:VCARD',
].join('\n');

describe('selected wallet vCard signing', () => {
  it('propagates active-wallet derivation failures without invoking signing', async () => {
    const { withSelectedWalletSigningKey } = await loadVCardSigning();
    let signingCalls = 0;

    expect(() => withSelectedWalletSigningKey(
      signingContext({
        deriveHDKey: () => { throw new Error('derivation failed'); },
      }),
      () => { signingCalls += 1; },
    )).toThrow('derivation failed');
    expect(signingCalls).toBe(0);
  });

  it('returns intentional unsigned outcome only without an active root or wallet', async () => {
    const { withSelectedWalletSigningKey } = await loadVCardSigning();
    let deriveCalls = 0;
    let signingCalls = 0;
    const context = signingContext({
      hdRoot: null,
      deriveHDKey: () => { deriveCalls += 1; },
    });

    expect(withSelectedWalletSigningKey(context, () => { signingCalls += 1; })).toBeUndefined();
    expect(withSelectedWalletSigningKey({ ...context, hdRoot: {}, wallet: null }, () => { signingCalls += 1; }))
      .toBeUndefined();
    expect(deriveCalls).toBe(0);
    expect(signingCalls).toBe(0);
  });

  it('does not return export artifacts when signing throws', async () => {
    const { createSignedVCardArtifacts } = await loadVCardSigning();
    let generated = 0;

    expect(() => createSignedVCardArtifacts(
      { firstName: 'Ada' },
      {
        generateVCard: () => {
          generated += 1;
          return UNSIGNED_VCARD;
        },
        signVCard: () => { throw new Error('derivation failed'); },
      },
    )).toThrow('derivation failed');
    expect(generated).toBe(1);
  });

  it('shows signed status only when the generated vCard contains a signature item', async () => {
    const {
      createSignedVCardArtifacts,
      getVCardSignatureStatus,
      updateVCardSignatureBadge,
    } = await loadVCardSigning();
    const badge = { style: {} };
    const artifacts = createSignedVCardArtifacts(
      { firstName: 'Ada' },
      {
        generateVCard: (_info, options) => options?.skipPhoto ? 'qr' : 'full',
        signVCard: (value) => value === 'full' ? SIGNED_VCARD : SIGNED_VCARD.replace('Ada Lovelace', 'QR'),
      },
    );

    expect(artifacts.signatureStatus).toBe('signed');
    expect(getVCardSignatureStatus(artifacts.vcard)).toBe('signed');
    expect(updateVCardSignatureBadge(badge, artifacts.vcard)).toBe('signed');
    expect(badge.style.display).toBe('flex');
  });

  it('hides signed status for an actually unsigned generated vCard', async () => {
    const { createSignedVCardArtifacts, updateVCardSignatureBadge } = await loadVCardSigning();
    const badge = { style: { display: 'flex' } };
    const artifacts = createSignedVCardArtifacts(
      { firstName: 'Ada' },
      {
        generateVCard: () => UNSIGNED_VCARD,
        signVCard: (value) => value,
      },
    );

    expect(artifacts.signatureStatus).toBe('unsigned');
    expect(updateVCardSignatureBadge(badge, artifacts.vcard)).toBe('unsigned');
    expect(badge.style.display).toBe('none');
  });
});
