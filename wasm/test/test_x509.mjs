/**
 * HD Wallet WASM - X.509 Tests
 */

import init, {
  Curve,
  X509Encoding,
} from '../src/index.mjs';

import { test, skip, assert, assertEqual, bytesToHex } from './test_all.mjs';

const wallet = await init();
assert(wallet.x509, 'X.509 API object must exist');
assertEqual(typeof wallet.x509.isAvailable, 'function', 'X.509 capability probe must exist');
const x509Available = wallet.x509.isAvailable();

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

if (!x509Available) {
  const reason = 'OpenSSL-backed X.509 support not available in this build';
  skip('X.509: private key PEM, self-signed certificate, and encoding conversion round-trip', reason);
  skip('X.509: issuer-signed certificate and PKCS#12 import/export round-trip', reason);
} else {
  test('X.509: private key PEM, self-signed certificate, and encoding conversion round-trip', () => {
    const certPrivateKey = wallet.x509.generatePrivateKey(Curve.P256);
    const certPrivateKeyPem = wallet.x509.exportPrivateKeyPem(Curve.P256, certPrivateKey);
    const importedPrivateKey = wallet.x509.importPrivateKeyPem(Curve.P256, certPrivateKeyPem);

    assert(certPrivateKeyPem.includes('BEGIN PRIVATE KEY'), 'Expected PKCS#8 PEM output');
    assertEqual(bytesToHex(importedPrivateKey), bytesToHex(certPrivateKey), 'Private key PEM round-trip should match');

    const certificatePem = wallet.x509.createSelfSignedCertificate(
      {
        subjectDn: 'CN=wallet.example,O=HD Wallet,C=US',
        serialHex: '0102A0',
        notBeforeUnix: 1704067200,
        notAfterUnix: 1735689600,
        dnsNames: ['wallet.example', 'api.wallet.example'],
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth', 'clientAuth'],
        walletAttestation: {
          curve: Curve.SECP256K1,
          privateKey: hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'),
          keyLabel: 'btc-main-0',
          commentPrefix: 'HDWALLET-X509'
        }
      },
      Curve.P256,
      certPrivateKey,
      X509Encoding.PEM
    );

    assert(typeof certificatePem === 'string', 'PEM certificate should be returned as string');
    assert(certificatePem.includes('BEGIN CERTIFICATE'), 'Expected PEM certificate output');

    const parsed = wallet.x509.parseCertificate(certificatePem, X509Encoding.PEM);
    assert(parsed.subjectDn.includes('CN=wallet.example'), 'Expected parsed subject DN');
    assertEqual(parsed.walletAttestationValid, true, 'Wallet attestation should validate');
    assertEqual(wallet.x509.verifyWalletAttestation(certificatePem, X509Encoding.PEM), true);

    const certificateDer = wallet.x509.convertCertificate(
      certificatePem,
      X509Encoding.PEM,
      X509Encoding.DER
    );
    assert(certificateDer instanceof Uint8Array, 'DER certificate should be returned as bytes');
    assert(certificateDer.length > 0, 'DER certificate should not be empty');

    const roundTripPem = wallet.x509.convertCertificate(
      certificateDer,
      X509Encoding.DER,
      X509Encoding.PEM
    );
    assert(typeof roundTripPem === 'string' && roundTripPem.includes('BEGIN CERTIFICATE'));
  });

  test('X.509: issuer-signed certificate and PKCS#12 import/export round-trip', () => {
    for (let i = 0; i < 5; i++) {
      const rootPrivateKey = wallet.x509.generatePrivateKey(Curve.P384);
      const leafPrivateKey = wallet.x509.generatePrivateKey(Curve.P384);

      const rootCertificatePem = wallet.x509.createSelfSignedCertificate(
        {
          subjectDn: 'CN=Wallet Root CA,O=HD Wallet,C=US',
          serialHex: '1001',
          notBeforeUnix: 1704067200,
          notAfterUnix: 1767225600,
          isCa: true,
          pathLen: 0,
          keyUsage: ['keyCertSign', 'cRLSign'],
          friendlyName: 'wallet-root'
        },
        Curve.P384,
        rootPrivateKey,
        X509Encoding.PEM
      );

      const leafCertificatePem = wallet.x509.issueCertificate(
        {
          subjectDn: 'CN=leaf.wallet.example,O=HD Wallet,C=US',
          serialHex: '1002',
          notBeforeUnix: 1704067200,
          notAfterUnix: 1735689600,
          dnsNames: ['leaf.wallet.example'],
          keyUsage: ['digitalSignature', 'keyEncipherment'],
          extendedKeyUsage: ['serverAuth'],
          friendlyName: 'wallet-leaf'
        },
        Curve.P384,
        rootPrivateKey,
        rootCertificatePem,
        X509Encoding.PEM,
        Curve.P384,
        leafPrivateKey,
        X509Encoding.PEM
      );

      const pkcs12 = wallet.x509.exportPkcs12(
        leafCertificatePem,
        X509Encoding.PEM,
        Curve.P384,
        leafPrivateKey,
        'changeit',
        'wallet-leaf',
        rootCertificatePem
      );

      assert(pkcs12 instanceof Uint8Array, `PKCS#12 export should return bytes (iteration ${i + 1})`);
      assert(pkcs12.length > 0, `PKCS#12 export should not be empty (iteration ${i + 1})`);

      const imported = wallet.x509.importPkcs12(pkcs12, 'changeit');
      assert(imported.certificatePem.includes('BEGIN CERTIFICATE'), `Imported PKCS#12 should include certificate PEM (iteration ${i + 1})`);
      assert(imported.privateKeyPem.includes('BEGIN PRIVATE KEY'), `Imported PKCS#12 should include private key PEM (iteration ${i + 1})`);
      assert(imported.chainPem.includes('BEGIN CERTIFICATE'), `Imported PKCS#12 should include chain PEM (iteration ${i + 1})`);
    }
  });
}
