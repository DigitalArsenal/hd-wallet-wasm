import { Buffer } from 'node:buffer';

import init, {
  HD_WALLET_SDN_PLUGIN_MANIFEST,
} from '../src/index.mjs';
import {
  decodeSdnPluginManifest,
  encodeSdnPluginManifest,
} from '../src/sdn-plugin-manifest-codec.mjs';
import {
  manifestBase64,
  manifestByteLength,
} from '../src/generated/sdn_plugin_manifest.mjs';
import {
  test,
  testAsync,
  assert,
  assertEqual,
  bytesToHex,
  hexToBytes,
} from './test_all.mjs';

const generatedManifestBytes = new Uint8Array(Buffer.from(manifestBase64, 'base64'));
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let wallet;
try {
  wallet = await init();
} catch (error) {
  console.log('  Skipping SDN plugin compliance tests: WASM module not available');
  process.exit(0);
}

function buildFrame(portId, schemaName, fileIdentifier, payload, overrides = {}) {
  return {
    portId,
    typeRef: {
      schemaName,
      fileIdentifier,
      schemaHash: [],
      acceptsAnyFlatbuffer: false,
    },
    alignment: 8,
    offset: overrides.offset ?? 0,
    size: overrides.size ?? 0,
    ownership: 'shared',
    generation: 0,
    mutability: 'immutable',
    traceId: overrides.traceId ?? `${schemaName}:${portId}`,
    streamId: overrides.streamId ?? 1,
    sequence: overrides.sequence ?? 1,
    payload,
  };
}

test('SDN plugin: generated PMAN bytes decode and round-trip', () => {
  assertEqual(
    generatedManifestBytes.length,
    manifestByteLength,
    'Generated manifest byte length should match the emitted metadata'
  );

  const decoded = decodeSdnPluginManifest(generatedManifestBytes);
  const reencoded = encodeSdnPluginManifest(decoded);

  assertEqual(
    decoded.pluginId,
    HD_WALLET_SDN_PLUGIN_MANIFEST.pluginId,
    'Decoded pluginId should match canonical source'
  );
  assertEqual(
    decoded.pluginFamily,
    'infrastructure',
    'Decoded manifest should retain the infrastructure plugin family'
  );
  assertDeepEqual(
    decoded.methods.map((method) => method.methodId),
    ['encrypt_fields', 'decrypt_fields', 'sign_detached', 'verify_detached'],
    'Decoded manifest should advertise the expected method ids'
  );
  assertDeepEqual(
    decoded.capabilities.map((capability) => capability.capabilityId),
    ['random', 'wallet_sign'],
    'Decoded manifest should retain the expected coarse capabilities'
  );
  assertEqual(
    bytesToHex(reencoded),
    bytesToHex(generatedManifestBytes),
    'Manifest bytes should round-trip through the codec deterministically'
  );
});

test('SDN plugin: embedded manifest exports return the generated PMAN bytes', () => {
  const embeddedBytes = wallet.plugin.getManifestBytes();
  const decoded = decodeSdnPluginManifest(embeddedBytes);

  assertEqual(
    wallet.plugin.manifestExports.bytesSymbol,
    'plugin_get_manifest_flatbuffer',
    'Manifest bytes export symbol should be canonical'
  );
  assertEqual(
    wallet.plugin.manifestExports.sizeSymbol,
    'plugin_get_manifest_flatbuffer_size',
    'Manifest size export symbol should be canonical'
  );
  assertEqual(
    bytesToHex(embeddedBytes),
    bytesToHex(generatedManifestBytes),
    'Embedded PMAN bytes should match the generated manifest artifact'
  );
  assertEqual(
    decoded.externalInterfaces.length,
    2,
    'Embedded manifest should retain explicit external interface declarations'
  );
  assertEqual(
    decoded.buildArtifacts.length,
    3,
    'Embedded manifest should document browser, WASI, and loader artifacts'
  );
  assertEqual(
    decoded.buildArtifacts[1].path,
    'wasm/dist/hd-wallet-wasi.wasm',
    'Embedded manifest should document the pure WASI artifact path'
  );
});

testAsync('SDN plugin: sign and verify methods invoke through the plugin contract', async () => {
  const plugin = wallet.plugin;
  const messageBytes = encoder.encode('sdn-plugin-signature');
  const signerPrivateKey = hexToBytes(
    '0000000000000000000000000000000000000000000000000000000000000001'
  );

  const signResult = plugin.invoke('sign_detached', {
    inputs: [
      buildFrame('message', 'DetachedSigningRequest.fbs', 'SGRQ', {
        curve: 'secp256k1',
        messageBytes,
        signerPrivateKey,
      }),
    ],
  });
  const signatureEnvelope = signResult.outputs[0].payload;

  assertEqual(
    signResult.outputs[0].portId,
    'signature',
    'sign_detached should emit on the signature output port'
  );
  assert(signatureEnvelope.signature.length >= 64, 'Detached signature should contain signature bytes');

  const verifyResult = plugin.invoke('verify_detached', {
    inputs: [
      buildFrame('signature', 'DetachedSignature.fbs', 'SIGD', signatureEnvelope),
    ],
  });
  const verification = verifyResult.outputs[0].payload;

  assertEqual(
    verification.valid,
    true,
    'verify_detached should accept the signature emitted by sign_detached'
  );
});

testAsync('SDN plugin: encrypt and decrypt methods invoke through the plugin contract', async () => {
  const plugin = wallet.plugin.withCapabilities({
    randomBytes(length) {
      return wallet.utils.getRandomBytes(length);
    },
  });
  const recipientPrivateKey = hexToBytes(
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
  );
  const senderPrivateKey = hexToBytes(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
  );
  const recipientPublicKey = wallet.curves.x25519.publicKey(recipientPrivateKey);
  const plaintext = encoder.encode('Classified observer note');

  const encryptResult = plugin.invoke('encrypt_fields', {
    inputs: [
      buildFrame('field_set', 'FieldSelectionBundle.fbs', 'FSLB', {
        curve: 'x25519',
        senderPrivateKey,
        recipientPublicKey,
        fields: [
          {
            fieldPath: 'observerNote',
            plaintext,
          },
        ],
      }),
    ],
  });
  const encryptedField = encryptResult.outputs[0].payload.fields[0];

  assertEqual(
    encryptResult.outputs[0].portId,
    'encrypted_fields',
    'encrypt_fields should emit on the encrypted_fields output port'
  );
  assert(
    bytesToHex(encryptedField.ciphertext) !== bytesToHex(plaintext),
    'Encrypted ciphertext should differ from the plaintext bytes'
  );

  const decryptResult = plugin.invoke('decrypt_fields', {
    inputs: [
      buildFrame('encrypted_fields', 'EncryptedFieldSet.fbs', 'EFLD', {
        curve: 'x25519',
        recipientPrivateKey,
        fields: [encryptedField],
      }),
    ],
  });
  const decryptedField = decryptResult.outputs[0].payload.fields[0];

  assertEqual(
    decryptResult.outputs[0].portId,
    'field_set',
    'decrypt_fields should emit on the field_set output port'
  );
  assertEqual(
    decoder.decode(decryptedField.plaintext),
    'Classified observer note',
    'decrypt_fields should recover the original plaintext'
  );
});

function assertDeepEqual(actual, expected, message) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    throw new Error(message || `Expected ${expectedJson}, got ${actualJson}`);
  }
}
