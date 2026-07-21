import assetReviewProtocol from '../../release/protocol/asset-review-v1.json' with { type: 'json' };

const textEncoder = new TextEncoder();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const getTypedArrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const getTypedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length').get;
const getArrayBufferByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const getSharedArrayBufferByteLength = typeof SharedArrayBuffer === 'undefined'
  ? null
  : Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'byteLength').get;

const IDENTITY_SCHEME = 'sdn-bip32-slip10-purpose-v1';
const SEED_PROFILE = 'password-scrypt-v2';
const JCS_SIGNATURE_PROFILE = 'ed25519-over-sha256-jcs-v1';
const RAW_SIGNATURE_PROFILE = 'ed25519-raw-32-v1';
const REVIEW_ORIGIN = 'https://review.spacedatanetwork.org';
const REVIEW_CLIENT_ID = 'sdn-asset-review-v1';
const REVIEW_AUDIENCE = 'asset-review:assets.ipfs.01';
const REVIEW_AUTHORITY_AUDIENCE = 'asset-review-authority:assets.ipfs.01';
const SDN_AUDIENCE = 'sdn-login:sdn.spaceaware.io';
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const LOWER_HEX_64 = /^[0-9a-f]{128}$/u;
const KEY_ID = /^sha256:[0-9a-f]{64}$/u;
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/u;
const CID_V1_RAW_SHA256 = /^b[a-z2-7]{58}$/u;
const BASE32_LOWER_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const MAX_WIRE_JSON_BYTES = 131_072;

const PUBLIC_IDENTITY_FIELDS = [
  'accountFingerprint',
  'accountIndex',
  'accountLabel',
  'accountPeerId',
  'accountXpub',
  'identityScheme',
  'keys',
  'schemaVersion',
  'seedProfile',
];
const KEY_DESCRIPTOR_FIELDS = [
  'bip32Fingerprint',
  'curve',
  'derivation',
  'encoding',
  'identityScheme',
  'keyId',
  'path',
  'publicKeyHex',
  'purpose',
  'seedProfile',
  'signatureProfile',
];
const CONNECTION_RESULT_FIELDS = [
  'connectionExpiresAt',
  'event',
  'identity',
  'schemaVersion',
];
const RAW_SIGNATURE_FIELDS = [
  'algorithm',
  'encoding',
  'identityScheme',
  'keyId',
  'schemaVersion',
  'signatureHex',
  'signatureProfile',
];
const CANONICAL_SIGNATURE_FIELDS = [
  'algorithm',
  'canonicalEnvelope',
  'encoding',
  'identityScheme',
  'keyId',
  'schemaVersion',
  'signatureHex',
  'signatureProfile',
  'signedDigestSha256',
];
const ACTIVATION_FIELDS = [
  'audience',
  'clientId',
  'expiresAt',
  'identityScheme',
  'issuedAt',
  'keyId',
  'nonce',
  'protocolVersion',
  'publicKeyHex',
  'purpose',
  'requestOrigin',
  'serviceInstance',
  'signatureProfile',
];
const DECISION_BASE_FIELDS = [
  'audience',
  'candidateKey',
  'challengeId',
  'clientId',
  'decision',
  'expiresAt',
  'issuedAt',
  'metadataSha256',
  'modelBytes',
  'modelCid',
  'modelSha256',
  'nonce',
  'previousDecisionHead',
  'protocolVersion',
  'requestOrigin',
];
const TRANSFORM_FIELDS = [
  'metersPerSourceUnit',
  'rotation',
  'scale',
  'sourceUnits',
  'translation',
  'upAxis',
];

function fail(message) {
  throw new TypeError(message);
}

function isObjectRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateUnicodeScalarString(value, label) {
  if (typeof value !== 'string') fail(`${label} must be a string`);
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    let scalar = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(index + 1);
      if (!(second >= 0xdc00 && second <= 0xdfff)) fail(`${label} contains an unpaired surrogate`);
      scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
      index += 1;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      fail(`${label} contains an unpaired surrogate`);
    }
    if ((scalar & 0xffff) === 0xfffe || (scalar & 0xffff) === 0xffff
      || (scalar >= 0xfdd0 && scalar <= 0xfdef)) {
      fail(`${label} contains a Unicode noncharacter`);
    }
  }
  return value;
}

function parseJsonWithoutDuplicates(text) {
  if (typeof text !== 'string') fail('wire JSON must be a string');
  if (textEncoder.encode(text).byteLength > MAX_WIRE_JSON_BYTES) fail('wire JSON is too large');
  if (text.charCodeAt(0) === 0xfeff) fail('wire JSON must not contain a BOM');
  let offset = 0;
  let tokens = 0;

  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  };

  const parseString = () => {
    if (text[offset] !== '"') fail('invalid JSON string');
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value;
        try {
          value = JSON.parse(text.slice(start, offset));
        } catch {
          fail('invalid JSON string');
        }
        return validateUnicodeScalarString(value, 'JSON string');
      }
      if (code < 0x20) fail('invalid JSON control character');
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length) fail('unterminated JSON escape');
      }
      offset += 1;
    }
    fail('unterminated JSON string');
  };

  const parseValue = (depth = 0) => {
    if (depth > 32) fail('wire JSON nesting is too deep');
    tokens += 1;
    if (tokens > 4096) fail('wire JSON contains too many values');
    skipWhitespace();
    const character = text[offset];
    if (character === '"') return parseString();
    if (character === '{') {
      offset += 1;
      const result = Object.create(null);
      const names = new Set();
      skipWhitespace();
      if (text[offset] === '}') {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        skipWhitespace();
        const name = parseString();
        if (names.has(name)) fail(`duplicate JSON field: ${name}`);
        names.add(name);
        skipWhitespace();
        if (text[offset] !== ':') fail('missing JSON object colon');
        offset += 1;
        result[name] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return result;
        }
        if (text[offset] !== ',') fail('invalid JSON object separator');
        offset += 1;
      }
      fail('unterminated JSON object');
    }
    if (character === '[') {
      offset += 1;
      const result = [];
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[offset] === ']') {
          offset += 1;
          return result;
        }
        if (text[offset] !== ',') fail('invalid JSON array separator');
        offset += 1;
      }
      fail('unterminated JSON array');
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    const numberMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(offset));
    if (!numberMatch) fail('invalid JSON value');
    offset += numberMatch[0].length;
    const value = Number(numberMatch[0]);
    if (!Number.isFinite(value)) fail('wire JSON number must be finite');
    return value;
  };

  skipWhitespace();
  const result = parseValue();
  skipWhitespace();
  if (offset !== text.length) fail('wire JSON contains trailing bytes');
  return result;
}

function readInput(value) {
  return typeof value === 'string' ? parseJsonWithoutDuplicates(value) : value;
}

function byteEqual(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function exactRecord(value, expectedFields, label) {
  const record = readInput(value);
  if (!isObjectRecord(record)) fail(`${label} must be a JSON object`);
  if (Object.getOwnPropertySymbols(record).length !== 0) fail(`${label} has an unknown symbol field`);
  const names = Object.getOwnPropertyNames(record).sort();
  const expected = [...expectedFields].sort();
  const encodedNames = textEncoder.encode(names.join('\u0000'));
  const encodedExpected = textEncoder.encode(expected.join('\u0000'));
  if (!byteEqual(encodedNames, encodedExpected)) fail(`${label} has missing or unknown fields`);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(record, name);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
      fail(`${label}.${name} must be an enumerable data field`);
    }
    if (descriptor.value === undefined) fail(`${label}.${name} must not be undefined`);
  }
  return record;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function frozenRecord(entries) {
  return deepFreeze(Object.fromEntries([...entries].sort(([left], [right]) => (
    left < right ? -1 : left > right ? 1 : 0
  ))));
}

function validatePlainDenseArray(value, length, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || value.length !== length) {
    fail(`${label} must be a plain array with exactly ${length} values`);
  }
  const expectedKeys = [...Array.from({ length }, (_, index) => String(index)), 'length'];
  const actualKeys = Reflect.ownKeys(value);
  if (actualKeys.length !== expectedKeys.length
      || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    fail(`${label} must be a dense plain array`);
  }
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
        || descriptor.value === undefined) {
      fail(`${label} must contain enumerable data values`);
    }
  }
}

function loadTransformPolicy(source) {
  const protocol = exactRecord(
    source,
    ['boundaryVectors', 'reviewedTransform', 'schemaVersion'],
    'asset review protocol policy',
  );
  exactLiteral(protocol.schemaVersion, 1, 'asset review protocol schemaVersion');
  const reviewed = exactRecord(protocol.reviewedTransform, [
    'metersPerSourceUnit',
    'quaternionNormTolerance',
    'scaleComponentExclusiveMin',
    'scaleComponentInclusiveMax',
    'translationComponentAbsMax',
    'upAxes',
  ], 'asset review transform policy');
  const meters = exactRecord(
    reviewed.metersPerSourceUnit,
    ['cm', 'km', 'm', 'mm'],
    'asset review unit policy',
  );
  for (const [unit, multiplier] of Object.entries(meters)) {
    if (typeof multiplier !== 'number' || !Number.isFinite(multiplier) || multiplier <= 0) {
      fail(`asset review unit policy ${unit} must be positive and finite`);
    }
  }
  for (const [name, number] of [
    ['quaternionNormTolerance', reviewed.quaternionNormTolerance],
    ['scaleComponentExclusiveMin', reviewed.scaleComponentExclusiveMin],
    ['scaleComponentInclusiveMax', reviewed.scaleComponentInclusiveMax],
    ['translationComponentAbsMax', reviewed.translationComponentAbsMax],
  ]) {
    if (typeof number !== 'number' || !Number.isFinite(number)) {
      fail(`asset review transform policy ${name} must be finite`);
    }
  }
  if (reviewed.quaternionNormTolerance <= 0
      || reviewed.scaleComponentInclusiveMax <= reviewed.scaleComponentExclusiveMin
      || reviewed.translationComponentAbsMax <= 0) {
    fail('asset review transform policy bounds are inconsistent');
  }
  validatePlainDenseArray(reviewed.upAxes, 3, 'asset review up-axis policy');
  if (reviewed.upAxes.join('\u0000') !== 'X_UP\u0000Y_UP\u0000Z_UP') {
    fail('asset review up-axis policy is invalid');
  }
  return frozenRecord([
    ['metersPerSourceUnit', frozenRecord(Object.entries(meters))],
    ['quaternionNormTolerance', reviewed.quaternionNormTolerance],
    ['scaleComponentExclusiveMin', reviewed.scaleComponentExclusiveMin],
    ['scaleComponentInclusiveMax', reviewed.scaleComponentInclusiveMax],
    ['translationComponentAbsMax', reviewed.translationComponentAbsMax],
    ['upAxes', Object.freeze(Array.from({ length: 3 }, (_, index) => reviewed.upAxes[index]))],
  ]);
}

const TRANSFORM_POLICY = loadTransformPolicy(assetReviewProtocol);

function exactLiteral(value, literal, label) {
  if (value !== literal) fail(`${label} must equal ${JSON.stringify(literal)}`);
  return value;
}

function exactOneOf(value, options, label) {
  if (!options.includes(value)) fail(`${label} is not an allowed value`);
  return value;
}

function exactPattern(value, pattern, label) {
  validateUnicodeScalarString(value, label);
  if (!pattern.test(value)) fail(`${label} has an invalid encoding`);
  return value;
}

function exactTimestamp(value, label) {
  validateUnicodeScalarString(value, label);
  if (!RFC3339_MILLISECONDS.test(value) || new Date(value).toISOString() !== value) {
    fail(`${label} must be exact RFC3339 milliseconds UTC`);
  }
  return value;
}

function validateLifetime(issuedAt, expiresAt) {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  if (!(expires > issued && expires - issued <= 300_000)) fail('request lifetime must be in (0, 300] seconds');
}

function encodeBase64url32(value, label) {
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array)
      || Object.getPrototypeOf(value) !== Uint8Array.prototype) {
    fail(`${label} must be a plain Uint8Array`);
  }
  const length = getTypedArrayLength.call(value);
  if (length !== 32) fail(`${label} must be exactly 32 bytes`);
  const expectedKeys = Array.from({ length: 32 }, (_, index) => String(index));
  const actualKeys = Reflect.ownKeys(value);
  if (actualKeys.length !== expectedKeys.length
      || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    fail(`${label} Uint8Array must contain only 32 indexed bytes`);
  }
  const buffer = getTypedArrayBuffer.call(value);
  let sharedBufferBrand = false;
  if (getSharedArrayBufferByteLength) {
    try {
      getSharedArrayBufferByteLength.call(buffer);
      sharedBufferBrand = true;
    } catch {
      sharedBufferBrand = false;
    }
  }
  if (sharedBufferBrand) {
    fail(`${label} must not use SharedArrayBuffer storage`);
  }
  try {
    getArrayBufferByteLength.call(buffer);
  } catch {
    fail(`${label} must use ArrayBuffer storage`);
  }
  const copy = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
        || !Number.isInteger(descriptor.value) || descriptor.value < 0 || descriptor.value > 255) {
      fail(`${label} Uint8Array contains an invalid indexed byte`);
    }
    copy[index] = value[index];
  }
  let binary = '';
  for (let index = 0; index < 32; index += 1) binary += String.fromCharCode(copy[index]);
  const encoded = globalThis.btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
  if (encoded.length !== 43) fail(`${label} did not encode to 43 base64url characters`);
  return encoded;
}

function validateBase64url32(value, label) {
  validateUnicodeScalarString(value, label);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) fail(`${label} must be canonical unpadded base64url`);
  let binary;
  try {
    binary = globalThis.atob(`${value.replace(/-/gu, '+').replace(/_/gu, '/')}=`);
  } catch {
    fail(`${label} must be valid base64url`);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength !== 32 || encodeBase64url32(bytes, label) !== value) {
    fail(`${label} must canonically encode exactly 32 bytes`);
  }
  return value;
}

function encodeBase32Lower(bytes) {
  let accumulator = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_LOWER_ALPHABET[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0) output += BASE32_LOWER_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

function validateModelCid(value, modelSha256) {
  validateUnicodeScalarString(value, 'modelCid');
  if (!CID_V1_RAW_SHA256.test(value)) fail('modelCid must be canonical CIDv1 raw sha2-256 base32');
  let accumulator = 0;
  let bits = 0;
  const decoded = [];
  for (const character of value.slice(1)) {
    const digit = BASE32_LOWER_ALPHABET.indexOf(character);
    if (digit < 0) fail('modelCid contains invalid base32');
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      decoded.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  if ((bits !== 0 && accumulator !== 0) || decoded.length !== 36) {
    fail('modelCid has noncanonical base32 tail bits or length');
  }
  const bytes = Uint8Array.from(decoded);
  if (bytes[0] !== 0x01 || bytes[1] !== 0x55 || bytes[2] !== 0x12 || bytes[3] !== 0x20) {
    fail('modelCid must encode CIDv1 raw sha2-256 with a 32-byte digest');
  }
  if (`b${encodeBase32Lower(bytes)}` !== value) fail('modelCid base32 is not canonical');
  let difference = 0;
  for (let index = 0; index < 32; index += 1) {
    const expected = Number.parseInt(modelSha256.slice(index * 2, index * 2 + 2), 16);
    difference |= bytes[index + 4] ^ expected;
  }
  if (difference !== 0) fail('modelCid digest does not match modelSha256');
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    validateUnicodeScalarString(value, 'canonical JSON string');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('canonical JSON numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isObjectRecord(value)) fail('canonical JSON contains an unsupported value');
  return `{${Object.keys(value).sort().map((name) => `${JSON.stringify(name)}:${canonicalJson(value[name])}`).join(',')}}`;
}

function validateEnvelopeDescriptor(value, signature) {
  for (const field of ['identityScheme', 'keyId', 'signatureProfile']) {
    if (value[field] !== signature[field]) fail(`canonicalEnvelope ${field} must match the signature result`);
  }
}

function validateSdnLoginEnvelope(value, signature) {
  const fields = [
    'audience',
    'challengeSha256',
    'clientId',
    'expiresAt',
    'identityScheme',
    'issuedAt',
    'keyId',
    'kind',
    'nonce',
    'protocolVersion',
    'requestOrigin',
    'signatureProfile',
  ];
  const envelope = exactRecord(value, fields, 'SDN login canonicalEnvelope');
  validateEnvelopeDescriptor(envelope, signature);
  exactLiteral(envelope.audience, SDN_AUDIENCE, 'SDN login envelope audience');
  exactPattern(envelope.challengeSha256, LOWER_HEX_32, 'SDN login envelope challengeSha256');
  exactLiteral(envelope.clientId, 'sdn-node-console-v1', 'SDN login envelope clientId');
  exactTimestamp(envelope.issuedAt, 'SDN login envelope issuedAt');
  exactTimestamp(envelope.expiresAt, 'SDN login envelope expiresAt');
  validateLifetime(envelope.issuedAt, envelope.expiresAt);
  exactLiteral(envelope.identityScheme, IDENTITY_SCHEME, 'SDN login envelope identityScheme');
  exactPattern(envelope.keyId, KEY_ID, 'SDN login envelope keyId');
  exactLiteral(envelope.kind, 'sdn-login', 'SDN login envelope kind');
  exactPattern(envelope.nonce, LOWER_HEX_32, 'SDN login envelope nonce');
  exactLiteral(envelope.protocolVersion, 2, 'SDN login envelope protocolVersion');
  exactLiteral(envelope.requestOrigin, 'https://sdn.spaceaware.io', 'SDN login envelope requestOrigin');
  exactLiteral(envelope.signatureProfile, JCS_SIGNATURE_PROFILE, 'SDN login envelope signatureProfile');
}

function validateActivationEnvelope(value, signature) {
  const envelope = exactRecord(
    value,
    [...ACTIVATION_FIELDS, 'kind'],
    'authority activation canonicalEnvelope',
  );
  validateEnvelopeDescriptor(envelope, signature);
  exactLiteral(envelope.kind, 'asset-review-authority-activation', 'activation envelope kind');
  validateActivation(Object.fromEntries(ACTIVATION_FIELDS.map((field) => [field, envelope[field]])));
}

function validateDecisionEnvelope(value, signature) {
  const conditionalFields = value?.decision === 'approve'
    ? ['note', 'reviewedTransform']
    : value?.decision === 'disapprove' ? ['reason'] : [];
  const requestFields = [...DECISION_BASE_FIELDS, ...conditionalFields];
  const envelope = exactRecord(value, [
    ...requestFields,
    'identityScheme',
    'keyId',
    'kind',
    'purpose',
    'signatureProfile',
  ], 'asset review decision canonicalEnvelope');
  validateEnvelopeDescriptor(envelope, signature);
  exactLiteral(envelope.identityScheme, IDENTITY_SCHEME, 'decision envelope identityScheme');
  exactPattern(envelope.keyId, KEY_ID, 'decision envelope keyId');
  exactLiteral(envelope.kind, 'asset-review-attestation', 'decision envelope kind');
  exactLiteral(envelope.purpose, 'asset-review-approval', 'decision envelope purpose');
  exactLiteral(envelope.signatureProfile, JCS_SIGNATURE_PROFILE, 'decision envelope signatureProfile');
  validateDecision(Object.fromEntries(requestFields.map((field) => [field, envelope[field]])));
}

function validateCanonicalEnvelope(value, expectedKind, signature) {
  validateUnicodeScalarString(value, 'canonicalEnvelope');
  if (textEncoder.encode(value).byteLength > MAX_WIRE_JSON_BYTES) fail('canonicalEnvelope is too large');
  const parsed = parseJsonWithoutDuplicates(value);
  if (!isObjectRecord(parsed) || parsed.kind !== expectedKind) fail('canonicalEnvelope kind does not match the operation');
  if (canonicalJson(parsed) !== value) fail('canonicalEnvelope must be exact JCS');
  if (expectedKind === 'sdn-login') validateSdnLoginEnvelope(parsed, signature);
  else if (expectedKind === 'asset-review-authority-activation') validateActivationEnvelope(parsed, signature);
  else if (expectedKind === 'asset-review-attestation') validateDecisionEnvelope(parsed, signature);
  else fail('canonicalEnvelope operation is not registered');
  return value;
}

function validateKeyDescriptor(input, expected) {
  const value = exactRecord(input, KEY_DESCRIPTOR_FIELDS, `identity key ${expected.purpose}`);
  exactLiteral(value.purpose, expected.purpose, 'key purpose');
  exactLiteral(value.identityScheme, IDENTITY_SCHEME, 'key identityScheme');
  exactLiteral(value.seedProfile, SEED_PROFILE, 'key seedProfile');
  exactLiteral(value.signatureProfile, expected.signatureProfile, 'key signatureProfile');
  exactLiteral(value.curve, expected.curve, 'key curve');
  exactLiteral(value.derivation, 'slip10', 'key derivation');
  exactLiteral(value.path, expected.path, 'key path');
  exactLiteral(value.encoding, 'raw', 'key encoding');
  exactPattern(value.publicKeyHex, LOWER_HEX_32, 'key publicKeyHex');
  exactLiteral(value.bip32Fingerprint, null, 'key bip32Fingerprint');
  exactPattern(value.keyId, KEY_ID, 'key keyId');
  return frozenRecord([
    ['bip32Fingerprint', null],
    ['curve', value.curve],
    ['derivation', 'slip10'],
    ['encoding', 'raw'],
    ['identityScheme', IDENTITY_SCHEME],
    ['keyId', value.keyId],
    ['path', value.path],
    ['publicKeyHex', value.publicKeyHex],
    ['purpose', value.purpose],
    ['seedProfile', SEED_PROFILE],
    ['signatureProfile', value.signatureProfile],
  ]);
}

function validatePublicIdentity(input) {
  const value = exactRecord(input, PUBLIC_IDENTITY_FIELDS, 'WalletPublicIdentity');
  exactLiteral(value.schemaVersion, 1, 'identity schemaVersion');
  exactLiteral(value.identityScheme, IDENTITY_SCHEME, 'identity identityScheme');
  exactLiteral(value.seedProfile, SEED_PROFILE, 'identity seedProfile');
  if (value.accountIndex !== 0) fail('public wallet identity must use account 0');
  exactLiteral(value.accountLabel, null, 'identity accountLabel');
  validateUnicodeScalarString(value.accountXpub, 'identity accountXpub');
  if (!/^xpub[1-9A-HJ-NP-Za-km-z]{107}$/u.test(value.accountXpub)) fail('identity accountXpub is invalid');
  validateUnicodeScalarString(value.accountPeerId, 'identity accountPeerId');
  if (!value.accountPeerId.startsWith('16Uiu2H') || value.accountPeerId.length < 40
      || value.accountPeerId.length > 64 || !BASE58.test(value.accountPeerId)) {
    fail('identity accountPeerId is invalid');
  }
  exactPattern(value.accountFingerprint, /^[0-9a-f]{8}$/u, 'identity accountFingerprint');
  validatePlainDenseArray(value.keys, 3, 'public identity keys array');
  const expected = [
    {
      purpose: 'asset-review-approval',
      curve: 'ed25519',
      signatureProfile: JCS_SIGNATURE_PROFILE,
      path: "m/44'/0'/0'/2'/0'",
    },
    {
      purpose: 'contact-encryption',
      curve: 'x25519',
      signatureProfile: null,
      path: "m/44'/0'/0'/1'/0'",
    },
    {
      purpose: 'sdn-authentication',
      curve: 'ed25519',
      signatureProfile: JCS_SIGNATURE_PROFILE,
      path: "m/44'/0'/0'/0'/0'",
    },
  ];
  const keys = Array.from(
    { length: 3 },
    (_, index) => validateKeyDescriptor(value.keys[index], expected[index]),
  );
  return frozenRecord([
    ['accountFingerprint', value.accountFingerprint],
    ['accountIndex', 0],
    ['accountLabel', null],
    ['accountPeerId', value.accountPeerId],
    ['accountXpub', value.accountXpub],
    ['identityScheme', IDENTITY_SCHEME],
    ['keys', deepFreeze(keys)],
    ['schemaVersion', 1],
    ['seedProfile', SEED_PROFILE],
  ]);
}

function validateConnectionResult(input, operation) {
  const value = exactRecord(input, CONNECTION_RESULT_FIELDS, `${operation} result`);
  exactLiteral(value.schemaVersion, 1, 'connection result schemaVersion');
  exactOneOf(value.event, ['connected', 'disconnected'], 'connection event');
  if (operation === 'connect' && value.event !== 'connected') fail('connect result must be connected');
  let identity = null;
  let connectionExpiresAt = null;
  if (value.event === 'connected') {
    identity = validatePublicIdentity(value.identity);
    connectionExpiresAt = exactTimestamp(value.connectionExpiresAt, 'connectionExpiresAt');
  } else if (value.identity !== null || value.connectionExpiresAt !== null) {
    fail('disconnected result must clear identity and expiry');
  }
  return frozenRecord([
    ['connectionExpiresAt', connectionExpiresAt],
    ['event', value.event],
    ['identity', identity],
    ['schemaVersion', 1],
  ]);
}

function validateRawSignature(input) {
  const value = exactRecord(input, RAW_SIGNATURE_FIELDS, 'raw signature');
  exactLiteral(value.schemaVersion, 1, 'signature schemaVersion');
  exactPattern(value.keyId, KEY_ID, 'signature keyId');
  exactOneOf(value.identityScheme, [
    'sdn-fast-password-auth-v1-legacy',
    'sdn-bip39-auth-v1-legacy',
  ], 'raw signature identityScheme');
  exactLiteral(value.algorithm, 'ed25519', 'signature algorithm');
  exactLiteral(value.encoding, 'raw', 'signature encoding');
  exactLiteral(value.signatureProfile, RAW_SIGNATURE_PROFILE, 'signature profile');
  exactPattern(value.signatureHex, LOWER_HEX_64, 'signatureHex');
  return frozenRecord([
    ['algorithm', 'ed25519'],
    ['encoding', 'raw'],
    ['identityScheme', value.identityScheme],
    ['keyId', value.keyId],
    ['schemaVersion', 1],
    ['signatureHex', value.signatureHex],
    ['signatureProfile', RAW_SIGNATURE_PROFILE],
  ]);
}

function validateCanonicalSignature(input, expectedKind) {
  const value = exactRecord(input, CANONICAL_SIGNATURE_FIELDS, 'canonical signature');
  exactLiteral(value.schemaVersion, 1, 'signature schemaVersion');
  exactPattern(value.keyId, KEY_ID, 'signature keyId');
  exactLiteral(value.identityScheme, IDENTITY_SCHEME, 'signature identityScheme');
  exactLiteral(value.algorithm, 'ed25519', 'signature algorithm');
  exactLiteral(value.encoding, 'raw', 'signature encoding');
  exactLiteral(value.signatureProfile, JCS_SIGNATURE_PROFILE, 'signature profile');
  validateCanonicalEnvelope(value.canonicalEnvelope, expectedKind, value);
  exactPattern(value.signedDigestSha256, LOWER_HEX_32, 'signedDigestSha256');
  exactPattern(value.signatureHex, LOWER_HEX_64, 'signatureHex');
  return frozenRecord([
    ['algorithm', 'ed25519'],
    ['canonicalEnvelope', value.canonicalEnvelope],
    ['encoding', 'raw'],
    ['identityScheme', IDENTITY_SCHEME],
    ['keyId', value.keyId],
    ['schemaVersion', 1],
    ['signatureHex', value.signatureHex],
    ['signatureProfile', JCS_SIGNATURE_PROFILE],
    ['signedDigestSha256', value.signedDigestSha256],
  ]);
}

function validateSdnLoginV1Wire(input) {
  const value = exactRecord(input, ['challengeBase64url', 'protocolVersion'], 'SDN login v1 request');
  exactLiteral(value.protocolVersion, 1, 'SDN login v1 protocolVersion');
  validateBase64url32(value.challengeBase64url, 'challengeBase64url');
  return frozenRecord([
    ['challengeBase64url', value.challengeBase64url],
    ['protocolVersion', 1],
  ]);
}

function validateSdnLoginV2Wire(input) {
  const value = exactRecord(input, [
    'audience',
    'challengeBase64url',
    'expiresAt',
    'issuedAt',
    'nonce',
    'protocolVersion',
  ], 'SDN login v2 request');
  exactLiteral(value.protocolVersion, 2, 'SDN login v2 protocolVersion');
  exactLiteral(value.audience, SDN_AUDIENCE, 'SDN login v2 audience');
  validateBase64url32(value.challengeBase64url, 'challengeBase64url');
  exactPattern(value.nonce, LOWER_HEX_32, 'SDN login nonce');
  exactTimestamp(value.issuedAt, 'SDN login issuedAt');
  exactTimestamp(value.expiresAt, 'SDN login expiresAt');
  validateLifetime(value.issuedAt, value.expiresAt);
  return frozenRecord([
    ['audience', SDN_AUDIENCE],
    ['challengeBase64url', value.challengeBase64url],
    ['expiresAt', value.expiresAt],
    ['issuedAt', value.issuedAt],
    ['nonce', value.nonce],
    ['protocolVersion', 2],
  ]);
}

function validateActivation(input) {
  const value = exactRecord(input, ACTIVATION_FIELDS, 'authority activation request');
  exactLiteral(value.protocolVersion, 1, 'activation protocolVersion');
  exactLiteral(value.audience, REVIEW_AUTHORITY_AUDIENCE, 'activation audience');
  exactLiteral(value.requestOrigin, REVIEW_ORIGIN, 'activation requestOrigin');
  exactLiteral(value.clientId, REVIEW_CLIENT_ID, 'activation clientId');
  exactLiteral(value.serviceInstance, 'assets.ipfs.01/asset-review-attestation', 'activation serviceInstance');
  exactLiteral(value.purpose, 'asset-review-authority-activation', 'activation purpose');
  exactPattern(value.nonce, LOWER_HEX_32, 'activation nonce');
  exactTimestamp(value.issuedAt, 'activation issuedAt');
  exactTimestamp(value.expiresAt, 'activation expiresAt');
  validateLifetime(value.issuedAt, value.expiresAt);
  exactPattern(value.publicKeyHex, LOWER_HEX_32, 'activation publicKeyHex');
  exactPattern(value.keyId, KEY_ID, 'activation keyId');
  exactLiteral(value.identityScheme, IDENTITY_SCHEME, 'activation identityScheme');
  exactLiteral(value.signatureProfile, JCS_SIGNATURE_PROFILE, 'activation signatureProfile');
  return frozenRecord(ACTIVATION_FIELDS.map((name) => [name, value[name]]));
}

function validateFiniteTuple(value, length, label) {
  validatePlainDenseArray(value, length, `${label} array`);
  const copy = Array.from({ length }, (_, index) => {
    const item = value[index];
    if (typeof item !== 'number' || !Number.isFinite(item)) fail(`${label} values must be finite numbers`);
    return item;
  });
  return deepFreeze(copy);
}

function validateTransform(input) {
  const value = exactRecord(input, TRANSFORM_FIELDS, 'reviewedTransform');
  const translation = validateFiniteTuple(value.translation, 3, 'translation');
  const rotation = validateFiniteTuple(value.rotation, 4, 'rotation');
  const scale = validateFiniteTuple(value.scale, 3, 'scale');
  if (translation.some((component) => Math.abs(component) > TRANSFORM_POLICY.translationComponentAbsMax)) {
    fail('translation values exceed the reviewed transform policy');
  }
  if (scale.some((component) => component <= TRANSFORM_POLICY.scaleComponentExclusiveMin
      || component > TRANSFORM_POLICY.scaleComponentInclusiveMax)) {
    fail('scale values exceed the reviewed transform policy');
  }
  const rotationNorm = Math.hypot(...rotation);
  if (Math.abs(rotationNorm - 1) > TRANSFORM_POLICY.quaternionNormTolerance) {
    fail('rotation must be a unit quaternion within the reviewed tolerance');
  }
  exactOneOf(value.upAxis, TRANSFORM_POLICY.upAxes, 'upAxis');
  validateUnicodeScalarString(value.sourceUnits, 'sourceUnits');
  if (!Object.hasOwn(TRANSFORM_POLICY.metersPerSourceUnit, value.sourceUnits)) {
    fail('sourceUnits is not allowed by the reviewed transform policy');
  }
  if (typeof value.metersPerSourceUnit !== 'number' || !Number.isFinite(value.metersPerSourceUnit)
      || value.metersPerSourceUnit !== TRANSFORM_POLICY.metersPerSourceUnit[value.sourceUnits]) {
    fail('metersPerSourceUnit must exactly match sourceUnits');
  }
  return frozenRecord([
    ['metersPerSourceUnit', value.metersPerSourceUnit],
    ['rotation', rotation],
    ['scale', scale],
    ['sourceUnits', value.sourceUnits],
    ['translation', translation],
    ['upAxis', value.upAxis],
  ]);
}

function isTrimScalar(scalar) {
  return (scalar >= 0x09 && scalar <= 0x0d) || scalar === 0x20 || scalar === 0x00a0
    || scalar === 0x1680 || (scalar >= 0x2000 && scalar <= 0x200a)
    || scalar === 0x2028 || scalar === 0x2029 || scalar === 0x202f || scalar === 0x205f
    || scalar === 0x3000 || scalar === 0xfeff;
}

function validateReviewText(value, label, nullable) {
  if (nullable && value === null) return null;
  validateUnicodeScalarString(value, label);
  if (value.length === 0 || textEncoder.encode(value).byteLength > 2000) fail(`${label} has an invalid length`);
  const scalars = Array.from(value, (character) => character.codePointAt(0));
  if (isTrimScalar(scalars[0]) || isTrimScalar(scalars[scalars.length - 1])) fail(`${label} must already be trimmed`);
  return value;
}

function validateDecision(input) {
  const raw = readInput(input);
  if (!isObjectRecord(raw)) fail('asset review decision request must be a JSON object');
  const decisionField = Object.getOwnPropertyDescriptor(raw, 'decision');
  if (!decisionField || !decisionField.enumerable || !('value' in decisionField)
      || decisionField.value === undefined) {
    fail('asset review decision request has an invalid decision field');
  }
  const decision = decisionField.value;
  const conditionalFields = decision === 'approve'
    ? ['note', 'reviewedTransform']
    : decision === 'disapprove' ? ['reason'] : [];
  const value = exactRecord(raw, [...DECISION_BASE_FIELDS, ...conditionalFields], 'asset review decision request');
  exactLiteral(value.protocolVersion, 1, 'decision protocolVersion');
  exactLiteral(value.audience, REVIEW_AUDIENCE, 'decision audience');
  exactLiteral(value.requestOrigin, REVIEW_ORIGIN, 'decision requestOrigin');
  exactLiteral(value.clientId, REVIEW_CLIENT_ID, 'decision clientId');
  exactPattern(value.challengeId, LOWER_HEX_32, 'challengeId');
  exactPattern(value.nonce, LOWER_HEX_32, 'decision nonce');
  exactTimestamp(value.issuedAt, 'decision issuedAt');
  exactTimestamp(value.expiresAt, 'decision expiresAt');
  validateLifetime(value.issuedAt, value.expiresAt);
  exactPattern(value.modelSha256, LOWER_HEX_32, 'modelSha256');
  exactPattern(value.metadataSha256, LOWER_HEX_32, 'metadataSha256');
  if (value.previousDecisionHead !== null) {
    exactPattern(value.previousDecisionHead, LOWER_HEX_32, 'previousDecisionHead');
  }
  validateModelCid(value.modelCid, value.modelSha256);
  if (!Number.isSafeInteger(value.modelBytes) || value.modelBytes <= 0) fail('modelBytes must be a positive safe integer');
  validateUnicodeScalarString(value.candidateKey, 'candidateKey');
  const candidatePrefix = 'asset-review:';
  const candidateSuffix = `:${value.modelSha256}`;
  if (!value.candidateKey.startsWith(candidatePrefix) || !value.candidateKey.endsWith(candidateSuffix)
      || textEncoder.encode(value.candidateKey).byteLength > 206) {
    fail('candidateKey does not bind the model digest');
  }
  const entityId = value.candidateKey.slice(candidatePrefix.length, -candidateSuffix.length);
  if (!/^[a-z0-9-]+\/[a-z0-9][a-z0-9-]*$/u.test(entityId)
      || textEncoder.encode(entityId).byteLength > 128) {
    fail('candidateKey entityId is invalid');
  }

  const output = DECISION_BASE_FIELDS.map((name) => [name, value[name]]);
  if (decision === 'approve') {
    output.push(['note', validateReviewText(value.note, 'note', true)]);
    output.push(['reviewedTransform', validateTransform(value.reviewedTransform)]);
  } else {
    output.push(['reason', validateReviewText(value.reason, 'reason', false)]);
  }
  const callerStringBytes = Object.values(value)
    .filter((item) => typeof item === 'string')
    .reduce((total, item) => total + textEncoder.encode(item).byteLength, 0);
  if (callerStringBytes > 16_384) fail('decision request strings exceed 16 KiB');
  return frozenRecord(output);
}

function buildEmptyRequest(input, label) {
  exactRecord(input, [], label);
  return deepFreeze({});
}

export function buildWalletConnectRequest(value = {}) {
  return buildEmptyRequest(value, 'wallet connect request');
}

export function parseWalletConnectRequest(value) {
  return buildEmptyRequest(value, 'wallet connect request');
}

export function buildWalletConnectResult(value) {
  return validateConnectionResult(value, 'connect');
}

export function parseWalletConnectResult(value) {
  return validateConnectionResult(value, 'connect');
}

export function buildWalletAccountRequest(value = {}) {
  return buildEmptyRequest(value, 'wallet account request');
}

export function parseWalletAccountRequest(value) {
  return buildEmptyRequest(value, 'wallet account request');
}

export function buildWalletAccountResult(value) {
  return validateConnectionResult(value, 'account');
}

export function parseWalletAccountResult(value) {
  return validateConnectionResult(value, 'account');
}

export function buildSdnLoginV1Request(input) {
  const value = exactRecord(input, ['challenge', 'protocolVersion'], 'SDN login v1 public request');
  exactLiteral(value.protocolVersion, 1, 'SDN login v1 protocolVersion');
  return validateSdnLoginV1Wire({
    challengeBase64url: encodeBase64url32(value.challenge, 'challenge'),
    protocolVersion: 1,
  });
}

export function parseSdnLoginV1Request(value) {
  return validateSdnLoginV1Wire(value);
}

export function buildSdnLoginV1Result(value) {
  return validateRawSignature(value);
}

export function parseSdnLoginV1Result(value) {
  return validateRawSignature(value);
}

export function buildSdnLoginV2Request(input) {
  const value = exactRecord(input, [
    'audience',
    'challenge',
    'expiresAt',
    'issuedAt',
    'nonce',
    'protocolVersion',
  ], 'SDN login v2 public request');
  return validateSdnLoginV2Wire({
    audience: value.audience,
    challengeBase64url: encodeBase64url32(value.challenge, 'challenge'),
    expiresAt: value.expiresAt,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
    protocolVersion: value.protocolVersion,
  });
}

export function parseSdnLoginV2Request(value) {
  return validateSdnLoginV2Wire(value);
}

export function buildSdnLoginV2Result(value) {
  return validateCanonicalSignature(value, 'sdn-login');
}

export function parseSdnLoginV2Result(value) {
  return validateCanonicalSignature(value, 'sdn-login');
}

export function buildAssetReviewAuthorityActivationRequest(value) {
  return validateActivation(value);
}

export function parseAssetReviewAuthorityActivationRequest(value) {
  return validateActivation(value);
}

export function buildAssetReviewAuthorityActivationResult(value) {
  return validateCanonicalSignature(value, 'asset-review-authority-activation');
}

export function parseAssetReviewAuthorityActivationResult(value) {
  return validateCanonicalSignature(value, 'asset-review-authority-activation');
}

export function buildAssetReviewDecisionRequest(value) {
  return validateDecision(value);
}

export function parseAssetReviewDecisionRequest(value) {
  return validateDecision(value);
}

export function buildAssetReviewDecisionResult(value) {
  return validateCanonicalSignature(value, 'asset-review-attestation');
}

export function parseAssetReviewDecisionResult(value) {
  return validateCanonicalSignature(value, 'asset-review-attestation');
}
