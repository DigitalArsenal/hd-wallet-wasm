import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { checkPublicBundleCrypto } from './public-bundle-crypto.mjs';

const repositoryDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const replyCipherSource = await readFile(join(repositoryDirectory, 'wallet-ui/client/reply-cipher.mjs'), 'utf8');

async function shippedPublicClient() {
  const manifest = JSON.parse(await readFile(join(repositoryDirectory, 'release/wallet-assets.v1.json'), 'utf8'));
  const url = new URL(manifest.assets.publicClientScript.url);
  return readFile(join(repositoryDirectory, 'release/static', url.pathname), 'utf8');
}

function seeded(source, from, to) {
  assert.ok(source.includes(from), `seed anchor is missing: ${from}`);
  const mutated = source.replace(from, to);
  assert.notEqual(mutated, source);
  return mutated;
}

function assertCaught(source, check) {
  const violations = checkPublicBundleCrypto(source);
  assert.ok(
    violations.some((violation) => violation.check === check),
    `expected ${check}, got ${JSON.stringify(violations, null, 2)}`,
  );
}

test('the reply cipher source and the shipped public client pass the boundary', async () => {
  assert.deepEqual(checkPublicBundleCrypto(replyCipherSource), []);
  assert.deepEqual(checkPublicBundleCrypto(await shippedPublicClient()), []);
});

const GENERATE = "subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])";
const EXPORT = "subtle.exportKey('raw', pair.publicKey)";
const HOLD = 'let privateKey = pair.privateKey;';
const ECDH = "subtle.deriveBits({ name: 'X25519', public: peer }, own, 256)";
const PEER = "subtle.importKey('raw', fromHex(ephemeralPublicKeyHex), { name: 'X25519' }, false, [])";
const HKDF_IMPORT = "subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])";
const AES_IMPORT = "subtle.importKey('raw', fieldKey, 'AES-CTR', false, ['decrypt'])";
const DECRYPT = "subtle.decrypt({ counter, length: 128, name: 'AES-CTR' }, key, ciphertext)";
const SUBTLE = 'const subtle = cryptoObject?.subtle;';

for (const [name, check, from, to] of [
  ['an extractable reply key', 'generate-key', GENERATE, GENERATE.replace('false', 'true')],
  ['a non-X25519 generated key', 'generate-key', GENERATE, GENERATE.replace("'X25519'", "'Ed25519'")],
  ['a second generated key', 'generate-key', `${GENERATE};`,
    `${GENERATE}; await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);`],
  ['an exported private key', 'export-key', EXPORT, "subtle.exportKey('pkcs8', pair.privateKey)"],
  ['a jwk public export', 'export-key', EXPORT, "subtle.exportKey('jwk', pair.publicKey)"],
  ['the private key leaving its binding', 'private-key-escape', HOLD, `${HOLD} globalThis.leak = privateKey;`],
  ['the private key in an object', 'private-key-escape', 'publicKeyHex: hex(publicKey),',
    'publicKeyHex: hex(publicKey), privateKey: pair.privateKey,'],
  ['ECDH with a foreign base key', 'derive-bits', ECDH, ECDH.replace('own,', 'peer,')],
  ['a non-X25519 deriveBits', 'derive-bits', ECDH, ECDH.replace("'X25519'", "'ECDH'")],
  ['HKDF over a wallet field context', 'hkdf-context', "encode('sdn-wallet-reply/v1')",
    "encode('sdn-field-encryption/v1|flatbuffers')"],
  ['HKDF over a BIP32 path', 'hkdf-context', 'fieldInfo(FIELD_LABEL, index)',
    "fieldInfo(new TextEncoder().encode(\"m/44'/0'/0'\"), index)"],
  ['a PBKDF2 key', 'kdf-literal', HKDF_IMPORT, HKDF_IMPORT.replace("'HKDF'", "'PBKDF2'")],
  ['an HKDF key outside the reply cipher', 'kdf-literal', SUBTLE, `${SUBTLE} const algorithm = 'HKDF';`],
  ['a pkcs8 import', 'import-key', PEER, PEER.replace("'raw'", "'pkcs8'")],
  ['an extractable import', 'import-key', HKDF_IMPORT, HKDF_IMPORT.replace('false', 'true')],
  ['an imported secret not made from the reply ECDH', 'import-key', AES_IMPORT,
    AES_IMPORT.replace('fieldKey', 'new Uint8Array(32)')],
  ['an X25519 import with usages', 'import-key', PEER, PEER.replace('[])', "['deriveBits'])")],
  ['a decrypt with a foreign counter', 'decrypt', DECRYPT, DECRYPT.replace('{ counter,', '{ counter: new Uint8Array(16),')],
  ['a decrypt under another algorithm', 'decrypt', DECRYPT, DECRYPT.replace("'AES-CTR'", "'AES-GCM'")],
  ['deriveKey', 'forbidden-method', SUBTLE,
    `${SUBTLE} await subtle.deriveKey({ name: 'X25519', public: peer }, own, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);`],
  ['wrapKey', 'forbidden-method', SUBTLE, `${SUBTLE} await subtle.wrapKey('raw', pair.publicKey, pair.publicKey, 'AES-KW');`],
  ['crypto.subtle handed out', 'subtle-escape', SUBTLE, `${SUBTLE} globalThis.s = subtle;`],
  ['a key method on an unproven object', 'subtle-escape', SUBTLE,
    `${SUBTLE} await cryptoObject.importKey('raw', new Uint8Array(32), 'AES-CTR', false, ['decrypt']);`],
  ['a renamed method by computed access', 'computed-guarded-name', PEER,
    PEER.replace('subtle.importKey(', "subtle['import' + 'Key'](")],
  ['a key method named in a literal', 'guarded-name-literal', SUBTLE, `${SUBTLE} const method = 'exportKey';`],
  ['an extra call site', 'inventory', DECRYPT, `${DECRYPT}, await ${DECRYPT}`],
]) {
  test(`the boundary refuses ${name} (${check})`, () => {
    assertCaught(seeded(replyCipherSource, from, to), check);
  });
}

test('the boundary reads the minified shipped bundle (an extractable reply key is refused)', async () => {
  const bundle = await shippedPublicClient();
  const anchor = 'generateKey({name:"X25519"},!1,["deriveBits"])';
  assertCaught(seeded(bundle, anchor, anchor.replace('!1', '!0')), 'generate-key');
});
