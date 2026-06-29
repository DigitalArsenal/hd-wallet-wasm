/**
 * EPM Attestation - canonical signing content (JCS) tests.
 *
 * These vectors are byte-identical to the in-module C++ verifier
 * (space-data-network-modules common/epm BuildSigningContent + common/jcs).
 * If these drift, wallet-signed EPMs stop verifying on the SDN node / wasmedge.
 */

import { test, assertEqual } from './test_all.mjs';
import { buildEPMSigningContent } from '../src/epm-attestation.mjs';

const decode = (bytes) => new TextDecoder().decode(bytes);

// Vector 1 — machine identity (ENTITY_TYPE + one signing key + timestamp).
// Mirrors common/epm/tests/epm_content_test.cpp vector #1 exactly.
test('EPM JCS: machine-identity vector matches in-module C++', () => {
  const epm = {
    ENTITY_TYPE: 'Individual',
    SIGNATURE_TIMESTAMP: 1782470000,
    KEYS: [
      { PUBLIC_KEY: 'aabbcc', XPUB: 'xpubTEST', ADDRESS_TYPE: 'ed25519', KEY_TYPE: 'Signing' },
    ],
    SIGNATURE: 'deadbeef', // must be excluded from signed content
  };
  const expect =
    '{"ENTITY_TYPE":"Individual","KEYS":[{"ADDRESS_TYPE":"ed25519","KEY_TYPE":"Signing",' +
    '"PUBLIC_KEY":"aabbcc","XPUB":"xpubTEST"}],"SIGNATURE_TIMESTAMP":1782470000}';
  assertEqual(decode(buildEPMSigningContent(epm)), expect, 'machine-identity canonical content');
});

// Vector 2 — trim whitespace, raw & < > (no HTML escaping), omit empties.
// Mirrors common/epm/tests/epm_content_test.cpp vector #2 exactly.
test('EPM JCS: trim + raw &<> + omit-empty matches in-module C++', () => {
  const epm = {
    ENTITY_TYPE: 'Organization',
    LEGAL_NAME: '  Acme & Co <Ltd>  ',
    DN: '',
    EMAIL: '   ',
  };
  const expect = '{"ENTITY_TYPE":"Organization","LEGAL_NAME":"Acme & Co <Ltd>"}';
  assertEqual(decode(buildEPMSigningContent(epm)), expect, 'trim/raw-&<>/omit-empty');
});

// Enum indices (as serialized in the FlatBuffer) must map to labels.
test('EPM JCS: ENTITY_TYPE/KEY_TYPE enum indices map to labels', () => {
  const node = decode(buildEPMSigningContent({ ENTITY_TYPE: 1 }));
  assertEqual(node, '{"ENTITY_TYPE":"Node"}', 'ENTITY_TYPE index 1 -> Node');

  const user = decode(buildEPMSigningContent({}));
  assertEqual(user, '{"ENTITY_TYPE":"User"}', 'missing ENTITY_TYPE -> User (FB default)');

  const keyByIndex = decode(
    buildEPMSigningContent({ ENTITY_TYPE: 0, KEYS: [{ PUBLIC_KEY: 'aa', KEY_TYPE: 1 }] }),
  );
  assertEqual(
    keyByIndex,
    '{"ENTITY_TYPE":"User","KEYS":[{"KEY_TYPE":"Encryption","PUBLIC_KEY":"aa"}]}',
    'KEY_TYPE index 1 -> Encryption',
  );
});

// JCS canonicalization properties: recursive key sort + no HTML escaping.
test('EPM JCS: recursive key sort + raw &<> in nested values', () => {
  const out = decode(
    buildEPMSigningContent({
      ENTITY_TYPE: 'User',
      ADDRESS: { STREET: 'b', COUNTRY: 'a', LOCALITY: 'c & <d>' },
    }),
  );
  // ADDRESS keys sorted COUNTRY < LOCALITY < STREET; & < > raw.
  assertEqual(
    out,
    '{"ADDRESS":{"COUNTRY":"a","LOCALITY":"c & <d>","STREET":"b"},"ENTITY_TYPE":"User"}',
    'nested sort + raw &<>',
  );
});

// SIGNATURE_TIMESTAMP is an integer and omitted when zero.
test('EPM JCS: SIGNATURE_TIMESTAMP integer, omitted when zero', () => {
  assertEqual(
    decode(buildEPMSigningContent({ ENTITY_TYPE: 'User', SIGNATURE_TIMESTAMP: 0 })),
    '{"ENTITY_TYPE":"User"}',
    'zero timestamp omitted',
  );
  assertEqual(
    decode(buildEPMSigningContent({ ENTITY_TYPE: 'User', SIGNATURE_TIMESTAMP: 1782470000 })),
    '{"ENTITY_TYPE":"User","SIGNATURE_TIMESTAMP":1782470000}',
    'integer timestamp included',
  );
});
