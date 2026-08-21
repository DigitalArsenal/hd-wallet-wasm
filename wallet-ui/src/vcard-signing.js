import { withDerivedPrivateKey } from './derived-key-scope.js';

export function withSelectedWalletSigningKey(context, operation) {
  const {
    hdRoot,
    wallet,
    buildSigningPath,
    deriveHDKey,
  } = context;
  if (!hdRoot || !wallet) return undefined;

  const accountIndex = wallet.accountIndex;
  const index = 0;
  const path = buildSigningPath(501, accountIndex, index);
  return withDerivedPrivateKey(
    () => deriveHDKey(path),
    (privateKey) => operation({ privateKey, accountIndex, index, path }),
  );
}

export function getVCardSignatureStatus(vcardText) {
  const lines = String(vcardText || '').split('\n');
  const signatureItems = new Set();

  for (const line of lines) {
    const label = line.match(/^item(\d+)\.X-ABLabel:Digital Signature(?:\s+#\d+)?\s*$/);
    if (label) signatureItems.add(label[1]);
  }

  const signed = lines.some((line) => {
    const value = line.match(/^item(\d+)\.X-ABRELATEDNAMES:(.+)$/);
    return Boolean(value && signatureItems.has(value[1]) && value[2].trim());
  });
  return signed ? 'signed' : 'unsigned';
}

export function createSignedVCardArtifacts(info, { generateVCard, signVCard }) {
  const vcard = signVCard(generateVCard(info));
  const vcardForQR = signVCard(generateVCard(info, { skipPhoto: true }));
  return {
    vcard,
    vcardForQR,
    signatureStatus: getVCardSignatureStatus(vcard),
  };
}

export function updateVCardSignatureBadge(badge, vcardText) {
  const status = getVCardSignatureStatus(vcardText);
  if (badge) badge.style.display = status === 'signed' ? 'flex' : 'none';
  return status;
}
