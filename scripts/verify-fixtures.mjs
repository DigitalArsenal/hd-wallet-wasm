import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);
const repositoryRealRoot = realpathSync.native(repositoryRoot);
assert(
  Number.isInteger(fsConstants.O_NOFOLLOW) && fsConstants.O_NOFOLLOW !== 0,
  'fixture verification requires a nonzero O_NOFOLLOW',
);

const INTEGRITY_PATH = 'test/fixtures/fixture-integrity.json';
const INTEGRITY_PATHS = [
  'release/protocol/asset-review-v1.json',
  'test/fixtures/sdn-operation-wire-v1.json',
  'test/fixtures/sdn-wallet-vectors.v1.json',
  'test/fixtures/trezor-bip39-vectors.json',
  'test/fixtures/trezor-bip39-vectors.source.json',
  'wallet-ui/data/common-passwords-sdn-v1.source.json',
  'wallet-ui/data/common-passwords-sdn-v1.txt',
];

const IDENTITY_SCHEME = 'sdn-bip32-slip10-purpose-v1';
const PASSWORD_PROFILE = 'password-scrypt-v2';
const SIGNATURE_PROFILE = 'ed25519-over-sha256-jcs-v1';
const RAW_SIGNATURE_PROFILE = 'ed25519-raw-32-v1';
const REVIEW_AUDIENCE = 'asset-review:assets.ipfs.01';
const AUTHORITY_AUDIENCE = 'asset-review-authority:assets.ipfs.01';
const REVIEW_CLIENT = 'sdn-asset-review-v1';
const REVIEW_ORIGIN = 'https://review.spacedatanetwork.org';
const SERVICE_INSTANCE = 'assets.ipfs.01/asset-review-attestation';
const AUTH_AUDIENCE = 'sdn-login:sdn.spaceaware.io';
const AUTH_CLIENT = 'sdn-node-console-v1';
const AUTH_ORIGIN = 'https://sdn.spaceaware.io';

const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder('utf-8', {
  fatal: true,
  ignoreBOM: false,
});
const utf8 = (value) => Buffer.from(encoder.encode(value));
const hex = (value) => Buffer.from(value).toString('hex');
const unhex = (value) => Buffer.from(value, 'hex');
const sha256 = (value) => createHash('sha256').update(value).digest();
const sha256Hex = (value) => sha256(value).toString('hex');
const range = (start) => Buffer.from(
  Array.from({ length: 32 }, (_, index) => start + index),
);

function absolute(relativePath) {
  assert.equal(typeof relativePath, 'string', 'fixture path must be a string');
  assert(relativePath.length > 0, 'fixture path must not be empty');
  assert.equal(
    relativePath.includes('\\'),
    false,
    `${relativePath} must use POSIX separators`,
  );
  assert.equal(
    path.posix.normalize(relativePath),
    relativePath,
    `${relativePath} must be a normalized POSIX relative path`,
  );
  assert.equal(path.isAbsolute(relativePath), false, `${relativePath} must be relative`);
  const resolved = path.resolve(repositoryRoot, relativePath);
  const repositoryRelative = path.relative(repositoryRoot, resolved);
  assert(
    repositoryRelative !== '..'
      && !repositoryRelative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(repositoryRelative),
    `${relativePath} escapes the repository`,
  );
  return resolved;
}

function assertSafeFixturePath(relativePath, resolved) {
  const repositoryRelative = path.relative(repositoryRoot, resolved);
  const components = repositoryRelative.split(path.sep);
  let candidate = repositoryRoot;
  let finalStat;
  for (let index = 0; index < components.length; index += 1) {
    candidate = path.join(candidate, components[index]);
    const stat = lstatSync(candidate);
    assert(
      !stat.isSymbolicLink(),
      `${relativePath} contains symlink component ${components
        .slice(0, index + 1)
        .join(path.sep)}`,
    );
    if (index < components.length - 1) {
      assert(
        stat.isDirectory(),
        `${relativePath} parent ${components.slice(0, index + 1).join(path.sep)} must be a directory`,
      );
    } else {
      assert(stat.isFile(), `${relativePath} must be a regular file`);
      finalStat = stat;
    }
  }
  assert.equal(
    realpathSync.native(resolved),
    path.join(repositoryRealRoot, repositoryRelative),
    `${relativePath} real path must remain inside the repository`,
  );
  return finalStat;
}

function readRegularFixture(relativePath) {
  const resolved = absolute(relativePath);
  assertSafeFixturePath(relativePath, resolved);
  let descriptor;
  let bytes;
  try {
    descriptor = openSync(
      resolved,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    const openedStat = fstatSync(descriptor);
    assert(openedStat.isFile(), `${relativePath} opened object must be a regular file`);
    const pathStat = assertSafeFixturePath(relativePath, resolved);
    assert.equal(openedStat.dev, pathStat.dev, `${relativePath} device changed during open`);
    assert.equal(openedStat.ino, pathStat.ino, `${relativePath} inode changed during open`);
    bytes = readFileSync(descriptor);
    const finalStat = assertSafeFixturePath(relativePath, resolved);
    assert.equal(openedStat.dev, finalStat.dev, `${relativePath} device changed during read`);
    assert.equal(openedStat.ino, finalStat.ino, `${relativePath} inode changed during read`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  assert(bytes.length > 0, `${relativePath} must not be empty`);
  assert.notDeepEqual(
    [...bytes.subarray(0, 3)],
    [0xef, 0xbb, 0xbf],
    `${relativePath} must not contain a BOM`,
  );
  assert.equal(bytes.includes(0x0d), false, `${relativePath} must not contain CR`);
  assert.equal(bytes.at(-1), 0x0a, `${relativePath} must end with LF`);
  assert.notEqual(bytes.at(-2), 0x0a, `${relativePath} must have one final LF`);
  fatalDecoder.decode(bytes);
  return bytes;
}

function isJsonNoncharacter(codePoint) {
  return Number.isInteger(codePoint)
    && codePoint >= 0
    && codePoint <= 0x10ffff
    && (
      (codePoint >= 0xfdd0 && codePoint <= 0xfdef)
      || (codePoint & 0xffff) === 0xfffe
      || (codePoint & 0xffff) === 0xffff
    );
}

function codePointLabel(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

function scanJsonNoDuplicates(raw) {
  let cursor = 0;
  let depth = 0;
  let tokens = 0;
  const fail = (message) => {
    throw new Error(`${message} at character ${cursor}`);
  };
  const token = () => {
    tokens += 1;
    if (tokens > 100000) fail('too many JSON tokens');
  };
  const whitespace = () => {
    while ('\t\n\r '.includes(raw[cursor] ?? '\0')) cursor += 1;
  };
  const string = () => {
    token();
    if (raw[cursor] !== '"') fail('expected JSON string');
    const start = cursor;
    cursor += 1;
    while (cursor < raw.length) {
      const code = raw.charCodeAt(cursor);
      if (code === 0x22) {
        cursor += 1;
        const value = JSON.parse(raw.slice(start, cursor));
        for (let index = 0; index < value.length; index += 1) {
          const unit = value.charCodeAt(index);
          let codePoint = unit;
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) fail('unpaired surrogate');
            codePoint = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
            index += 1;
          } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            fail('unpaired surrogate');
          }
          if (isJsonNoncharacter(codePoint)) {
            fail(`JSON noncharacter ${codePointLabel(codePoint)}`);
          }
        }
        return value;
      }
      if (code < 0x20) fail('unescaped control character');
      if (code === 0x5c) {
        cursor += 1;
        const escape = raw[cursor];
        if (!escape || !'"\\/bfnrtu'.includes(escape)) fail('invalid escape');
        if (escape === 'u') {
          const encoded = raw.slice(cursor + 1, cursor + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(encoded)) fail('invalid Unicode escape');
          cursor += 4;
        }
      }
      cursor += 1;
    }
    return fail('unterminated JSON string');
  };
  const number = () => {
    token();
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      raw.slice(cursor),
    );
    if (!match) fail('invalid JSON number');
    cursor += match[0].length;
    if (!Number.isFinite(Number(match[0]))) fail('non-finite JSON number');
  };
  const value = () => {
    whitespace();
    const current = raw[cursor];
    if (current === '"') return string();
    if (current === '{') {
      token();
      depth += 1;
      if (depth > 128) fail('JSON nesting is too deep');
      cursor += 1;
      whitespace();
      const keys = new Set();
      if (raw[cursor] === '}') {
        cursor += 1;
        depth -= 1;
        return;
      }
      while (true) {
        const key = string();
        if (keys.has(key)) fail(`duplicate JSON key ${key}`);
        keys.add(key);
        whitespace();
        if (raw[cursor] !== ':') fail('expected colon');
        cursor += 1;
        value();
        whitespace();
        if (raw[cursor] === '}') {
          cursor += 1;
          depth -= 1;
          return;
        }
        if (raw[cursor] !== ',') fail('expected comma');
        cursor += 1;
        whitespace();
      }
    }
    if (current === '[') {
      token();
      depth += 1;
      if (depth > 128) fail('JSON nesting is too deep');
      cursor += 1;
      whitespace();
      if (raw[cursor] === ']') {
        cursor += 1;
        depth -= 1;
        return;
      }
      while (true) {
        value();
        whitespace();
        if (raw[cursor] === ']') {
          cursor += 1;
          depth -= 1;
          return;
        }
        if (raw[cursor] !== ',') fail('expected comma');
        cursor += 1;
      }
    }
    for (const literal of ['true', 'false', 'null']) {
      if (raw.startsWith(literal, cursor)) {
        token();
        cursor += literal.length;
        return;
      }
    }
    number();
  };
  value();
  whitespace();
  if (cursor !== raw.length) fail('trailing JSON data');
}

function parseJsonFixture(relativePath, { pretty = true } = {}) {
  const bytes = readRegularFixture(relativePath);
  const raw = fatalDecoder.decode(bytes);
  scanJsonNoDuplicates(raw);
  const value = JSON.parse(raw);
  if (pretty) {
    assert.equal(
      raw,
      `${JSON.stringify(value, null, 2)}\n`,
      `${relativePath} must use two-space JSON and one LF`,
    );
  }
  return value;
}

function jcsString(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    let codePoint = unit;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      assert(
        next >= 0xdc00 && next <= 0xdfff,
        `${label} contains an unpaired surrogate`,
      );
      codePoint = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
      index += 1;
    } else {
      assert(
        !(unit >= 0xdc00 && unit <= 0xdfff),
        `${label} contains an unpaired surrogate`,
      );
    }
    assert(
      !isJsonNoncharacter(codePoint),
      `${label} contains JSON noncharacter ${codePointLabel(codePoint)}`,
    );
  }
  return JSON.stringify(value);
}

function jcs(value) {
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return jcsString(value, 'JCS string');
  if (typeof value === 'number') {
    assert(Number.isFinite(value), 'JCS number must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  assert(value && typeof value === 'object', 'value must be JSON');
  return `{${Object.keys(value)
    .sort()
    .map((key) => {
      assert.notEqual(value[key], undefined, `undefined JCS field ${key}`);
      return `${jcsString(key, 'JCS object key')}:${jcs(value[key])}`;
    })
    .join(',')}}`;
}

function verifyNoncharacterRejection() {
  const codePoints = [
    ...Array.from({ length: 0x20 }, (_, index) => 0xfdd0 + index),
    ...Array.from(
      { length: 0x11 },
      (_, plane) => [plane * 0x10000 + 0xfffe, plane * 0x10000 + 0xffff],
    ).flat(),
  ];
  for (const codePoint of codePoints) {
    const value = String.fromCodePoint(codePoint);
    const label = `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
    assert.throws(
      () => scanJsonNoDuplicates(JSON.stringify({ [value]: 'safe' })),
      /JSON noncharacter/u,
      `scanner key ${label}`,
    );
    assert.throws(
      () => scanJsonNoDuplicates(JSON.stringify({ safe: value })),
      /JSON noncharacter/u,
      `scanner value ${label}`,
    );
    assert.throws(
      () => jcs({ [value]: 'safe' }),
      /JSON noncharacter/u,
      `JCS key ${label}`,
    );
    assert.throws(
      () => jcs({ safe: value }),
      /JSON noncharacter/u,
      `JCS value ${label}`,
    );
  }
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} object`);
  assert.deepEqual(Object.keys(value), expected, `${label} exact keys/order`);
}

function lowerHex(value, bytes, label) {
  assert.equal(typeof value, 'string', `${label} string`);
  assert.match(value, new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u'), label);
  return unhex(value);
}

function canonicalBase64url32(value, label) {
  assert.equal(typeof value, 'string', `${label} string`);
  assert.match(value, /^[A-Za-z0-9_-]{43}$/u, label);
  const bytes = Buffer.from(value, 'base64url');
  assert.equal(bytes.length, 32, `${label} decoded length`);
  assert.equal(bytes.toString('base64url'), value, `${label} canonical encoding`);
  return bytes;
}

function assertKeyId(publicKeyHex, keyId, label) {
  const publicKey = lowerHex(publicKeyHex, 32, `${label} public key`);
  assert.equal(keyId, `sha256:${sha256Hex(publicKey)}`, `${label} key ID`);
  return publicKey;
}

function ed25519PublicKey(raw) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: 'der',
    type: 'spki',
  });
}

function assertEd25519(publicKey, message, signatureHex, label) {
  const signature = lowerHex(signatureHex, 64, `${label} signature`);
  assert(
    verifySignature(null, message, ed25519PublicKey(publicKey), signature),
    `${label} Ed25519 verification`,
  );
}

function verifyIntegrity() {
  const integrity = parseJsonFixture(INTEGRITY_PATH);
  exactKeys(integrity, ['schemaVersion', 'hashAlgorithm', 'entries'], 'fixture integrity');
  assert.equal(integrity.schemaVersion, 1);
  assert.equal(integrity.hashAlgorithm, 'sha256');
  assert(Array.isArray(integrity.entries), 'fixture integrity entries');
  assert.deepEqual(
    integrity.entries.map((entry) => entry.path),
    INTEGRITY_PATHS,
    'fixture integrity exact ASCII-sorted path set',
  );
  assert.deepEqual([...INTEGRITY_PATHS].sort(), INTEGRITY_PATHS);
  assert.equal(new Set(INTEGRITY_PATHS).size, INTEGRITY_PATHS.length);
  for (const entry of integrity.entries) {
    exactKeys(entry, ['path', 'bytes', 'sha256'], `integrity ${entry.path}`);
    assert.equal(typeof entry.path, 'string');
    assert.match(entry.path, /^[\x20-\x7e]+$/u);
    assert(Number.isSafeInteger(entry.bytes) && entry.bytes > 0, `${entry.path} byte count`);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/u, `${entry.path} digest`);
    const bytes = readRegularFixture(entry.path);
    assert.equal(bytes.length, entry.bytes, `${entry.path} byte length`);
    assert.equal(sha256Hex(bytes), entry.sha256, `${entry.path} SHA-256`);
  }
}

const passwordSourceExpected = {
  schemaVersion: 1,
  name: 'SecLists 10k most common passwords',
  upstreamRepository: 'https://github.com/danielmiessler/SecLists',
  upstreamRelease: '2026.1',
  upstreamCommit: '190c6f7bd58c847ceadfe57d9853592737f059e8',
  sourcePath: 'Passwords/Common-Credentials/10k-most-common.txt',
  sourceUrl:
    'https://raw.githubusercontent.com/danielmiessler/SecLists/190c6f7bd58c847ceadfe57d9853592737f059e8/Passwords/Common-Credentials/10k-most-common.txt',
  license: 'MIT',
  bytes: 73017,
  sha256: '4adb3f0afb4a10cf19ebe48d8c69a46f934bbc8d77c694c210564f9583e7f4ba',
};

const trezorSourceExpected = {
  schemaVersion: 1,
  name: 'Trezor BIP-39 test vectors',
  upstreamRepository: 'https://github.com/trezor/python-mnemonic',
  upstreamCommit: 'b57a5ad77a981e743f4167ab2f7927a55c1e82a8',
  sourcePath: 'vectors.json',
  sourceUrl:
    'https://raw.githubusercontent.com/trezor/python-mnemonic/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json',
  license: 'MIT',
  bytes: 152400,
  sha256: 'fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8',
};

function verifySources() {
  const passwordSource = parseJsonFixture(
    'wallet-ui/data/common-passwords-sdn-v1.source.json',
  );
  exactKeys(passwordSource, [
    'schemaVersion', 'name', 'upstreamRepository', 'upstreamRelease',
    'upstreamCommit', 'sourcePath', 'sourceUrl', 'license', 'bytes', 'sha256',
  ], 'password source metadata');
  assert.deepEqual(
    passwordSource,
    passwordSourceExpected,
  );
  const trezorSource = parseJsonFixture(
    'test/fixtures/trezor-bip39-vectors.source.json',
  );
  exactKeys(trezorSource, [
    'schemaVersion', 'name', 'upstreamRepository', 'upstreamCommit',
    'sourcePath', 'sourceUrl', 'license', 'bytes', 'sha256',
  ], 'Trezor source metadata');
  assert.deepEqual(
    trezorSource,
    trezorSourceExpected,
  );
  const passwordBytes = readRegularFixture(
    'wallet-ui/data/common-passwords-sdn-v1.txt',
  );
  assert.equal(passwordBytes.length, 73017);
  assert.equal(sha256Hex(passwordBytes), passwordSourceExpected.sha256);
  const passwords = fatalDecoder.decode(passwordBytes).trimEnd().split('\n');
  assert.equal(passwords.length, 10000, 'password corpus count');
  assert.equal(new Set(passwords).size, 10000, 'password corpus uniqueness');
  assert(
    passwords.every(
      (value) => /^[\x21-\x7e]+$/u.test(value) && value === value.toLowerCase(),
    ),
    'password corpus lowercase printable ASCII',
  );
  assert(passwords.includes('password'), 'password corpus expected sentinel');

  const trezorBytes = readRegularFixture('test/fixtures/trezor-bip39-vectors.json');
  assert.equal(trezorBytes.length, 152400);
  assert.equal(sha256Hex(trezorBytes), trezorSourceExpected.sha256);
  scanJsonNoDuplicates(fatalDecoder.decode(trezorBytes));
}

const expectedNewAccounts = [
  {
    index: 0,
    accountPath: "m/44'/0'/0'",
    accountXpub:
      'xpub6D9SXNXfAWtnHw8uWqUwMCBFh4R5bvzzWWemXtzwNhojQnYXyQARwhphkvtN4AJ93QFhzzHQZHj7MYQ7KuQ8vsXiTEwUq6MiF7iaLXTPFRT',
    peerId: '16Uiu2HAkzgWPa6HTtNTU8WQi1kppaRsYUDBxNKygQNYUk7N73CMA',
    fingerprint: '9b582711',
    authentication: {
      path: "m/44'/0'/0'/0'/0'",
      publicKeyHex: 'f5b8e91319472049d552f37d58f528eecefd68cfc4c462c6fcff279c76afb319',
      keyId: 'sha256:d997ad2bf7dbf21c490695eba54d3054628d7f7fb9037fb8145ea32b4e384b7c',
    },
    contactEncryption: {
      path: "m/44'/0'/0'/1'/0'",
      publicKeyHex: '1349c6136a8765e4b2a8795037cc6233e22d31a08c76e328ad247daf836c6c0c',
    },
    assetReviewApproval: {
      path: "m/44'/0'/0'/2'/0'",
      publicKeyHex: '9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff',
      keyId: 'sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d',
    },
  },
  {
    index: 1,
    accountPath: "m/44'/0'/1'",
    accountXpub:
      'xpub6D9SXNXfAWtnLsmiHP7yjWHAmZoYMgp6yWLMr42BWdpgyE6mTNAukCm2PW5AdEG33RTxNgKg42cUE69zrundhquxbWj8sHe2jxtDb3VFoT4',
    peerId: '16Uiu2HAm4ZJR19pVznz3KFcQYjjnyCwcspueFV19m7ca5CVPWy3b',
    fingerprint: 'e8214de1',
    authentication: {
      path: "m/44'/0'/1'/0'/0'",
      publicKeyHex: '999b912a96fde6be3e718f573c29f16cc97d13fd128c2eb6a7d089af7c0fc2b0',
      keyId: 'sha256:72a40224fc9ba6c1ddeaa4f6da6cd53ab6015f591b76f77c984a6b7d4573b9ef',
    },
    contactEncryption: {
      path: "m/44'/0'/1'/1'/0'",
      publicKeyHex: 'd03c2cd449e689c1f93c17f53bc08cb3f55ecb5c3accf6c1e86b14e9bdf6a610',
    },
    assetReviewApproval: {
      path: "m/44'/0'/1'/2'/0'",
      publicKeyHex: '8225fc858d41aa082ac813b8b613dcc282e285090363de2ff80bff182eeb18d0',
      keyId: 'sha256:791e490a08f2a1616fc7fd610e4a9a1f28fdfd0205c429ddeb7902420ec9ad14',
    },
  },
];

const expectedPrimitiveAccounts = [
  {
    index: 0,
    accountXpub:
      'xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj',
    peerId: '16Uiu2HAmLggak6WGB3dqbUkX22r4jScmzPY6AsPC4HAp6MTGGoYx',
    fingerprint: '6cc9f252',
    authPublicKeyHex: '7c2e79f3a1701fb2a86a2c24a3fdf8634b7aad80886c0c0a526d44d23fe8e19a',
    authKeyId: 'sha256:687194ce6572b9e8685c870cc2d9cfba469aa3b66ec1f343fc2b1c876020418b',
    approvalPublicKeyHex: 'd8c1129d890a4284b71c6371648aef7fb8d8582ceeffc8b6d363c3394744fc68',
    approvalKeyId: 'sha256:bbe69296944bfd7b0e7ac68328bd585ad976d4b5eaf5f3d6c19053cb86032090',
    encryptionPublicKeyHex: '654f607c4395ac0599a6c38bc34315dd6644f405218daa4ec5318068f008a364',
    raw32PrimitiveSignatureHex:
      'd1631f8386e88bc21985f7a166a2c37c3b635541df6c0190193399675722f420d6f6a2a193184af5c807a972a015fc1270210f3f742885177a86f0264bdfb40b',
  },
  {
    index: 1,
    accountXpub:
      'xpub6BosfCnifzxcJJ1wYuntGJfF2zPJkDeG9ELNHcKNjezuea4tumswN9sH1psMdSVqCMoJC21Bv8usSeqSP4Sp1tLzW7aY59fGn9GCYzx5UTo',
    peerId: '16Uiu2HAm1gk13fMSW7eKuDozaQfEpZ5xaTLXf3q4iQUhRttSUbfE',
    fingerprint: 'f11b5622',
    authPublicKeyHex: '2967ced1299600604535a92865e8ff21e70cfd9b55091d43c9a29192dc48ffa6',
    authKeyId: 'sha256:d1809e09af2a55be623e3d2dcb0702a012178fad47971dea830656b0328136f8',
    approvalPublicKeyHex: 'b6eee58dca925872201f76ce10783d13d8eaeba68bf502cf017ab778d9cea819',
    approvalKeyId: 'sha256:c78235491aa5d821a46858527c107848dd4cbe93cdc61d4cea3b6e2a432aa567',
    encryptionPublicKeyHex: '052889798f4abafaf8111bb1a3e4b407ceb438ab3a510057db8538a613aa7050',
    raw32PrimitiveSignatureHex:
      '8308abb0a54b7a6dd7c6784c38d50bd06fbf417c0aa712cfa976246ee854bb095854ec9ddedb6cc9d7e5157e840b79e4f1d2169b7535cc23705397605e551809',
  },
];

const expectedLegacyIdentities = [
  {
    "name": "legacy-fast-password",
    "identityScheme": "sdn-fast-password-auth-v1-legacy",
    "seedProfile": "password-fast-v1-legacy",
    "source": {
      "kind": "password",
      "rawUsername": "fixture-legacy-user",
      "rawUsernameUtf8Hex": "666978747572652d6c65676163792d75736572",
      "password": "Fixture-Only-Legacy-Secret-0001!",
      "passwordUtf8Hex": "466978747572652d4f6e6c792d4c65676163792d5365637265742d3030303121"
    },
    "seedHex": "ac83330e5389d0910c2684cc9840ff139f3d98b0a2b6092bc6a711dc349cc5a3dafef19a460d5c7d16788e8f06c1b79036bd23b68f7614cd17094a6a1ce204fe",
    "rootPublicIdentity": {
      "accountXpub": "xpub661MyMwAqRbcEfyzy7yani8iGiX4LEVVYDjA2na9Lo9mxsi1jLShZ5Z6wM5KaCWVZ1sUDR9m1qLU7QpehwBTRMQqgLRVZwCTMPfTihVSmHj",
      "peerId": "16Uiu2HAmFp8YKnXBybMTpeRaxrVL8R6xu8nPTsigvijdCRwi4FsC",
      "fingerprint": "21e59eba"
    },
    "accounts": [
      {
        "index": 0,
        "historicalStatus": "released-v2.0.19",
        "authentication": {
          "path": "m/44'/0'/0'/0/0",
          "publicKeyHex": "019a0da9799107657f72d4ae3d5e483b51e7b46b0428f8695fc5412efdb178b4",
          "keyId": "sha256:0d5b0e5c9371eea56a7c20ff27e6c0759d93c26794a4cea91c25f0ffafc4c1da",
          "rawChallengeBase64url": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
          "signatureHex": "16afa44dee296c85350922a10e64e7d8faeb3ad77747c050794140a08974df5af7bcee1bf27fbe8eb36bea25c9c3bc4470a03dd801b36d58edd64e6e45b93203"
        }
      },
      {
        "index": 1,
        "historicalStatus": "specified-account-1-extension",
        "authentication": {
          "path": "m/44'/0'/1'/0/0",
          "publicKeyHex": "9128643341847661c3f05bc20245a9719bc98b29ea784ebe512ca2636b0c744b",
          "keyId": "sha256:f39aaef64b015de3c01bbfd6561c86ea5cb9d4a822b0c982093646da353aafd5",
          "rawChallengeBase64url": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
          "signatureHex": "67fdc308b5214ea4356268b61fd030eb31a2622cc15fa332c84eb5812283ae5ea1969320cb03f7e4243e60f6e6ccea7de117fab679a92a45ad36689ec0122e0b"
        }
      }
    ]
  },
  {
    "name": "legacy-bip39-mnemonic",
    "identityScheme": "sdn-bip39-auth-v1-legacy",
    "seedProfile": "bip39-mnemonic-v1-legacy",
    "source": {
      "kind": "mnemonic",
      "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "passphrase": ""
    },
    "seedHex": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    "rootPublicIdentity": {
      "accountXpub": "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
      "peerId": "16Uiu2HAmTG7RvuHZSbFpFugPwQdSKG9weCGNvTaiJFbrUqiXZyMm",
      "fingerprint": "73c5da0a"
    },
    "accounts": [
      {
        "index": 0,
        "historicalStatus": "released-v2.0.19",
        "authentication": {
          "path": "m/44'/0'/0'/0/0",
          "publicKeyHex": "3c35d187ea9428787cb3343d4a724fc961902012bbce5ce4f43369861e19127f",
          "keyId": "sha256:840c4084865fc7153bcef07c5458e1bae11370539f3b9106542db552dcc10115",
          "rawChallengeBase64url": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",
          "signatureHex": "542957a9ba75ca30e639637d79575ae8a6868e1a3923a3b2f9e4e91bf99cf8134f0b9ef90a224bca094efb8b264b6a75477433c5e835699c5e0aaf972f9bbf03"
        }
      },
      {
        "index": 1,
        "historicalStatus": "specified-account-1-extension",
        "authentication": {
          "path": "m/44'/0'/1'/0/0",
          "publicKeyHex": "3525c32858ce80473ee9bdc1d580fde43bd6e640b8c19583f9160b2efc116e91",
          "keyId": "sha256:b8aece28623ce188040068c43558930c6fe4eee83c6730ea680831c64cfd1072",
          "rawChallengeBase64url": "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
          "signatureHex": "ea5c1aeb77a6201a49f8926cde019f5a8bfa3563b957184cc1d668f9edea3c98ac415b740dd48f6a651e2755ca637d9ecf875b059c2cc5543dbc8a7045f2f704"
        }
      }
    ]
  }
];

const expectedPasswordVectors = [
  {
    name: 'alice-account-source',
    rawUsername: '  ALICE_01  ',
    rawUsernameUtf8Hex: '2020414c4943455f30312020',
    canonicalUsername: 'alice_01',
    password: 'Correct Horse Battery Staple!',
    passwordUtf8Hex: '436f727265637420486f727365204261747465727920537461706c6521',
    seedHex:
      'c63fbe791b92d91eb828eab4b203cffe7f333e9d200ec2355d77c7796c080f79c9ed753af213bf155512e3c667c3be26a22c1c599cbae52cb44add279559fe5b',
  },
  {
    name: 'review-owner-decomposed',
    rawUsername: 'Review-Owner',
    rawUsernameUtf8Hex: '5265766965772d4f776e6572',
    canonicalUsername: 'review-owner',
    password: 'Café-Bridge-2026!🚀',
    passwordUtf8Hex: '43616665cc812d4272696467652d3230323621f09f9a80',
    seedHex:
      '82a9851cafe5f364980fab1b4fbc6ed0160f788286200572e14a324ec404ebf1f84e68ca995d5bc04f540afaad67ceb5276fb754104aff574328cec200809939',
  },
  {
    name: 'review-owner-composed',
    rawUsername: 'Review-Owner',
    rawUsernameUtf8Hex: '5265766965772d4f776e6572',
    canonicalUsername: 'review-owner',
    password: 'Café-Bridge-2026!🚀',
    passwordUtf8Hex: '436166c3a92d4272696467652d3230323621f09f9a80',
    seedHex:
      'fdb155a9da6f464fb5cfb58a5150cf4f9ea56dbb56c45e786ebacc6130089cfd6f62bba7a0eaa9b809a9a9eb9acb07bd697515dd5cf7b77f8099ddec598a845d',
  },
];

function expectedUsernameCases() {
  const row = (name, inputEncoding, inputHex, canonicalUsername, error) => ({
    name,
    inputEncoding,
    inputHex,
    accepted: error === null,
    canonicalUsername,
    error,
  });
  return [
    row('username-ascii-trim-case', 'utf8-hex', '2020414c4943455f30312020', 'alice_01', null),
    row('username-min-length', 'utf8-hex', '616263', 'abc', null),
    row('username-max-length', 'utf8-hex', '61'.repeat(64), 'a'.repeat(64), null),
    row('username-too-short', 'utf8-hex', '6162', null, 'username-format'),
    row('username-too-long', 'utf8-hex', '61'.repeat(65), null, 'username-format'),
    row('username-raw-byte-limit', 'utf8-hex', `${'20'.repeat(192)}${'61'.repeat(64)}`, 'a'.repeat(64), null),
    row('username-raw-byte-over-limit', 'utf8-hex', `${'20'.repeat(193)}${'61'.repeat(64)}`, null, 'username-byte-length'),
    row('username-all-spaces', 'utf8-hex', '202020', null, 'username-format'),
    row('username-leading-nbsp', 'utf8-hex', 'c2a0616263', null, 'username-format'),
    row('username-leading-tab', 'utf8-hex', '09616263', null, 'username-format'),
    row('username-non-ascii', 'utf8-hex', '616cc3ad6365', null, 'username-format'),
    row('username-invalid-utf8', 'utf8-hex', 'c0af', null, 'invalid-utf8'),
    row('username-lone-high-surrogate', 'utf16-code-units-be-hex', 'd800', null, 'invalid-utf8'),
    row('username-lone-low-surrogate', 'utf16-code-units-be-hex', 'dc00', null, 'invalid-utf8'),
  ];
}

const acceptedPasswordSeeds = new Map([
  ['password-scalars-12', '2f45991bd2d206a37b4458fdfaf44fa140320739e2296b644efad831c7d1ebde646075b8df71f59d0329e1b0a03e6e1d369490744f660c768722e9ceedb00ecc'],
  ['password-scalars-128', '00573087a154c2fe215e7ce4435ee81af25e5d68ba6de290558ff6b9125f85e180b43a04648ef232fcfe1179f2f3f0c66996baef3c769f75d9449be4b2e4d64b'],
  ['password-bytes-255', 'b66b66970b8846600ad3d52e59e5ae00fe17eb034015ec17cf5fdef3f6a76e2a7af3ba2fc99b5491bb54887d7d422ddd25d48e0159196d20158316b13a1fa2a5'],
  ['password-bytes-256', 'ef2712f1cfe228bdf79de560e1318c0a3b6a1c20227893db3c10f9869e1aef596dd310990f8c73615fdc8a7df044f80ca466c88bac8ba0f84ed43a8442e27a95'],
  ['password-noncommon-internal-spaces', '5434a6eacf650e431f02a613457c23c4792d3ad09649f04d3b039f7806a48ff32608e40972afa95204ea1e5e7abbf65543cea8475129571dfd5d66e1d10ed903'],
  ['password-decomposed', expectedPasswordVectors[1].seedHex],
  ['password-composed', expectedPasswordVectors[2].seedHex],
]);

function expectedPasswordCases() {
  const row = (name, inputEncoding, inputHex, error) => ({
    name,
    inputEncoding,
    inputHex,
    accepted: error === null,
    seedHex: error === null ? acceptedPasswordSeeds.get(name) : null,
    error,
  });
  const invalidScalar = 'invalid-password-scalar';
  const whitespace = 'password-all-whitespace';
  return [
    row('password-scalars-11', 'utf8-hex', `4121${'78'.repeat(9)}`, 'password-length'),
    row('password-scalars-12', 'utf8-hex', `4121${'78'.repeat(10)}`, null),
    row('password-scalars-128', 'utf8-hex', `4121${'78'.repeat(126)}`, null),
    row('password-scalars-129', 'utf8-hex', `4121${'78'.repeat(127)}`, 'password-length'),
    row('password-bytes-255', 'utf8-hex', `${'c3a9'.repeat(127)}21`, null),
    row('password-bytes-256', 'utf8-hex', 'c3a9'.repeat(128), null),
    row('password-bytes-257', 'utf8-hex', `${'c3a9'.repeat(127)}e282ac`, 'password-byte-length'),
    row('password-lone-high-surrogate', 'utf16-code-units-be-hex', `00410021d800${'0078'.repeat(9)}`, 'invalid-utf8'),
    row('password-lone-low-surrogate', 'utf16-code-units-be-hex', `00410021dc00${'0078'.repeat(9)}`, 'invalid-utf8'),
    row('password-invalid-utf8', 'utf8-hex', `4121c0af${'78'.repeat(9)}`, 'invalid-utf8'),
    row('password-control-u0000', 'utf8-hex', `412100${'78'.repeat(9)}`, invalidScalar),
    row('password-control-u0001', 'utf8-hex', `412101${'78'.repeat(9)}`, invalidScalar),
    row('password-control-u001f', 'utf8-hex', `41211f${'78'.repeat(9)}`, invalidScalar),
    row('password-control-u007f', 'utf8-hex', `41217f${'78'.repeat(9)}`, invalidScalar),
    row('password-control-u0080', 'utf8-hex', `4121c280${'78'.repeat(9)}`, invalidScalar),
    row('password-control-u009f', 'utf8-hex', `4121c29f${'78'.repeat(9)}`, invalidScalar),
    ...[
      ['u0020', '20'], ['u00a0', 'c2a0'], ['u1680', 'e19a80'],
      ['u2000', 'e28080'], ['u2001', 'e28081'], ['u2002', 'e28082'],
      ['u2003', 'e28083'], ['u2004', 'e28084'], ['u2005', 'e28085'],
      ['u2006', 'e28086'], ['u2007', 'e28087'], ['u2008', 'e28088'],
      ['u2009', 'e28089'], ['u200a', 'e2808a'], ['u2028', 'e280a8'],
      ['u2029', 'e280a9'], ['u202f', 'e280af'], ['u205f', 'e2819f'],
      ['u3000', 'e38080'],
    ].map(([name, encoded]) => row(`password-whitespace-${name}`, 'utf8-hex', encoded.repeat(12), whitespace)),
    row('password-whitespace-mixed', 'utf8-hex', '20c2a0e19a80e28080e28081e28082e28083e28084e28085e28086e28087e28088e28089e2808ae280a8e280a9e280afe2819fe38080', whitespace),
    row('password-common-ascii-fold', 'utf8-hex', '202050415353574f52442020', 'common-password'),
    row('password-noncommon-internal-spaces', 'utf8-hex', '2020436f727265637420486f727365204261747465727920537461706c65212020', null),
    row('password-decomposed', 'utf8-hex', '43616665cc812d4272696467652d3230323621f09f9a80', null),
    row('password-composed', 'utf8-hex', '436166c3a92d4272696467652d3230323621f09f9a80', null),
  ];
}

const importPaths = {
  new0: ["m/44'/0'/0'", "m/44'/0'/0'/0'/0'", "m/44'/0'/0'/1'/0'", "m/44'/0'/0'/2'/0'"],
  legacy0: ['m', "m/44'/0'/0'/0/0", null, null],
  new2: ["m/44'/0'/2'", "m/44'/0'/2'/0'/0'", "m/44'/0'/2'/1'/0'", "m/44'/0'/2'/2'/0'"],
  swapped: ["m/44'/0'/0'", "m/44'/0'/0'/2'/0'", "m/44'/0'/0'/1'/0'", "m/44'/0'/0'/0'/0'"],
  nonhard: ["m/44'/0'/0'", "m/44'/0'/0'/0/0'", "m/44'/0'/0'/1'/0'", "m/44'/0'/0'/2'/0'"],
};

function importRow(name, identityScheme, seedProfile, accountIndex, pathRow, signatureProfile, accepted, error) {
  return {
    name,
    identityScheme,
    seedProfile,
    accountIndex,
    accountPath: pathRow[0],
    authenticationPath: pathRow[1],
    contactEncryptionPath: pathRow[2],
    assetReviewApprovalPath: pathRow[3],
    signatureProfile,
    accepted,
    error,
  };
}

function expectedIdentityImports() {
  return [
    importRow('identity-valid-new', IDENTITY_SCHEME, PASSWORD_PROFILE, 0, importPaths.new0, SIGNATURE_PROFILE, true, null),
    importRow('identity-valid-legacy-fast', 'sdn-fast-password-auth-v1-legacy', 'password-fast-v1-legacy', 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, true, null),
    importRow('identity-valid-legacy-mnemonic', 'sdn-bip39-auth-v1-legacy', 'bip39-mnemonic-v1-legacy', 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, true, null),
    importRow('identity-account-2', IDENTITY_SCHEME, PASSWORD_PROFILE, 2, importPaths.new2, SIGNATURE_PROFILE, false, 'account-index'),
    importRow('identity-swapped-auth-approval', IDENTITY_SCHEME, PASSWORD_PROFILE, 0, importPaths.swapped, SIGNATURE_PROFILE, false, 'path'),
    importRow('identity-nonhardened-slip10', IDENTITY_SCHEME, PASSWORD_PROFILE, 0, importPaths.nonhard, SIGNATURE_PROFILE, false, 'path'),
    importRow('identity-unknown-scheme', 'sdn-unknown-v1', PASSWORD_PROFILE, 0, importPaths.new0, SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-unknown-seed-profile', IDENTITY_SCHEME, 'password-unknown-v1', 0, importPaths.new0, SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-unknown-signature-profile', IDENTITY_SCHEME, PASSWORD_PROFILE, 0, importPaths.new0, 'ed25519-unknown-v1', false, 'signature-profile'),
    importRow('identity-mixed-new-fast', IDENTITY_SCHEME, 'password-fast-v1-legacy', 0, importPaths.new0, SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-mixed-new-mnemonic', IDENTITY_SCHEME, 'bip39-mnemonic-v1-legacy', 0, importPaths.new0, SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-mixed-fast-password-v2', 'sdn-fast-password-auth-v1-legacy', PASSWORD_PROFILE, 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-mixed-fast-mnemonic', 'sdn-fast-password-auth-v1-legacy', 'bip39-mnemonic-v1-legacy', 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-mixed-mnemonic-password-v2', 'sdn-bip39-auth-v1-legacy', PASSWORD_PROFILE, 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, false, 'identity-pair'),
    importRow('identity-mixed-mnemonic-fast', 'sdn-bip39-auth-v1-legacy', 'password-fast-v1-legacy', 0, importPaths.legacy0, RAW_SIGNATURE_PROFILE, false, 'identity-pair'),
  ];
}

function verifyWalletVectors() {
  const vectors = parseJsonFixture('test/fixtures/sdn-wallet-vectors.v1.json');
  exactKeys(vectors, [
    'schemaVersion', 'newIdentity', 'purposeSeparatedMnemonicPrimitive',
    'legacySource', 'legacyIdentities', 'leadingZeroFingerprint',
    'validationCases', 'operationMatrix',
  ], 'wallet vectors');
  assert.equal(vectors.schemaVersion, 1);
  exactKeys(vectors.newIdentity, [
    'identityScheme', 'seedProfile', 'identitySource', 'passwordVectors', 'accounts',
  ], 'new identity');
  assert.equal(vectors.newIdentity.identityScheme, IDENTITY_SCHEME);
  assert.equal(vectors.newIdentity.seedProfile, PASSWORD_PROFILE);
  assert.equal(vectors.newIdentity.identitySource, 'password-scrypt-v2-ascii');
  for (const passwordVector of vectors.newIdentity.passwordVectors) {
    exactKeys(passwordVector, [
      'name', 'rawUsername', 'rawUsernameUtf8Hex', 'canonicalUsername',
      'password', 'passwordUtf8Hex', 'seedHex',
    ], `password vector ${passwordVector.name}`);
  }
  assert.deepEqual(vectors.newIdentity.passwordVectors, expectedPasswordVectors);
  assert.notEqual(
    vectors.newIdentity.passwordVectors[1].seedHex,
    vectors.newIdentity.passwordVectors[2].seedHex,
  );
  assert.deepEqual(vectors.newIdentity.accounts, expectedNewAccounts);
  assert.deepEqual(
    vectors.newIdentity.accounts.map((account) => account.index),
    [0, 1],
    'new account indices/order',
  );
  for (const account of vectors.newIdentity.accounts) {
    exactKeys(account, [
      'index', 'accountPath', 'accountXpub', 'peerId', 'fingerprint',
      'authentication', 'contactEncryption', 'assetReviewApproval',
    ], `new account ${account.index}`);
    exactKeys(
      account.authentication,
      ['path', 'publicKeyHex', 'keyId'],
      `new authentication account ${account.index}`,
    );
    exactKeys(
      account.contactEncryption,
      ['path', 'publicKeyHex'],
      `new contact encryption account ${account.index}`,
    );
    exactKeys(
      account.assetReviewApproval,
      ['path', 'publicKeyHex', 'keyId'],
      `new asset approval account ${account.index}`,
    );
    assert.match(account.fingerprint, /^[0-9a-f]{8}$/u);
    assertKeyId(account.authentication.publicKeyHex, account.authentication.keyId, `auth account ${account.index}`);
    assertKeyId(account.assetReviewApproval.publicKeyHex, account.assetReviewApproval.keyId, `approval account ${account.index}`);
    lowerHex(account.contactEncryption.publicKeyHex, 32, `contact account ${account.index}`);
  }

  const primitive = vectors.purposeSeparatedMnemonicPrimitive;
  exactKeys(primitive, [
    'vectorKind', 'importable', 'operationEligible', 'mnemonic', 'passphrase',
    'rootXpub', 'raw32PrimitiveChallengeBase64url', 'accounts',
  ], 'mnemonic primitive');
  assert.equal(primitive.vectorKind, 'derivation-primitive-only');
  assert.equal(primitive.importable, false);
  assert.equal(primitive.operationEligible, false);
  assert.equal(Object.hasOwn(primitive, 'identityScheme'), false);
  assert.equal(Object.hasOwn(primitive, 'seedProfile'), false);
  assert.equal(
    primitive.mnemonic,
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  assert.equal(primitive.passphrase, '');
  assert.equal(
    primitive.rootXpub,
    'xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8',
  );
  const primitiveChallenge = canonicalBase64url32(
    primitive.raw32PrimitiveChallengeBase64url,
    'mnemonic primitive challenge',
  );
  assert.equal(hex(primitiveChallenge), hex(range(0)));
  assert.equal(primitive.accounts.length, 2);
  assert.deepEqual(
    primitive.accounts.map((account) => account.index),
    [0, 1],
    'mnemonic primitive account indices/order',
  );
  assert.deepEqual(
    primitive.accounts,
    expectedPrimitiveAccounts,
    'mnemonic primitive reviewed literals',
  );
  for (const account of primitive.accounts) {
    exactKeys(account, [
      'index', 'accountXpub', 'peerId', 'fingerprint', 'authPublicKeyHex',
      'authKeyId', 'approvalPublicKeyHex', 'approvalKeyId',
      'encryptionPublicKeyHex', 'raw32PrimitiveSignatureHex',
    ], `mnemonic primitive account ${account.index}`);
    const authKey = assertKeyId(account.authPublicKeyHex, account.authKeyId, `primitive auth ${account.index}`);
    assertKeyId(account.approvalPublicKeyHex, account.approvalKeyId, `primitive approval ${account.index}`);
    lowerHex(account.encryptionPublicKeyHex, 32, `primitive contact ${account.index}`);
    assertEd25519(authKey, primitiveChallenge, account.raw32PrimitiveSignatureHex, `primitive account ${account.index}`);
  }

  exactKeys(vectors.legacySource, [
    'repository', 'tag', 'commit', 'passwordKdfSource', 'loginCallbackSource',
    'pathHelperSource',
  ], 'legacy source');
  assert.deepEqual(vectors.legacySource, {
    repository: 'https://github.com/DigitalArsenal/hd-wallet-wasm.git',
    tag: 'v2.0.19',
    commit: '537ac9a08c12fb62a7152007bce9898efb6f9204',
    passwordKdfSource: 'wallet-ui/src/app.js:382-403',
    loginCallbackSource: 'wallet-ui/src/app.js:2635-2657',
    pathHelperSource: 'wasm/src/index.mjs:4597-4666',
  });
  assert.equal(vectors.legacyIdentities.length, 2);
  assert.deepEqual(
    vectors.legacyIdentities,
    expectedLegacyIdentities,
    'legacy identity reviewed literals',
  );
  const expectedLegacyPairs = [
    ['legacy-fast-password', 'sdn-fast-password-auth-v1-legacy', 'password-fast-v1-legacy'],
    ['legacy-bip39-mnemonic', 'sdn-bip39-auth-v1-legacy', 'bip39-mnemonic-v1-legacy'],
  ];
  for (let identityIndex = 0; identityIndex < vectors.legacyIdentities.length; identityIndex += 1) {
    const identity = vectors.legacyIdentities[identityIndex];
    exactKeys(identity, [
      'name', 'identityScheme', 'seedProfile', 'source', 'seedHex',
      'rootPublicIdentity', 'accounts',
    ], `legacy identity ${identityIndex}`);
    assert.deepEqual(
      [identity.name, identity.identityScheme, identity.seedProfile],
      expectedLegacyPairs[identityIndex],
    );
    exactKeys(
      identity.source,
      identity.source.kind === 'password'
        ? ['kind', 'rawUsername', 'rawUsernameUtf8Hex', 'password', 'passwordUtf8Hex']
        : ['kind', 'mnemonic', 'passphrase'],
      `${identity.name} source`,
    );
    lowerHex(identity.seedHex, 64, `${identity.name} seed`);
    exactKeys(identity.rootPublicIdentity, ['accountXpub', 'peerId', 'fingerprint'], `${identity.name} root`);
    assert.match(identity.rootPublicIdentity.fingerprint, /^[0-9a-f]{8}$/u);
    assert.equal(identity.accounts.length, 2);
    assert.deepEqual(
      identity.accounts.map((account) => account.index),
      [0, 1],
      `${identity.name} account indices/order`,
    );
    for (const account of identity.accounts) {
      exactKeys(account, ['index', 'historicalStatus', 'authentication'], `${identity.name} account ${account.index}`);
      assert.equal(
        account.historicalStatus,
        account.index === 0 ? 'released-v2.0.19' : 'specified-account-1-extension',
      );
      exactKeys(account.authentication, [
        'path', 'publicKeyHex', 'keyId', 'rawChallengeBase64url', 'signatureHex',
      ], `${identity.name} auth ${account.index}`);
      assert.equal(account.authentication.path, `m/44'/0'/${account.index}'/0/0`);
      const publicKey = assertKeyId(
        account.authentication.publicKeyHex,
        account.authentication.keyId,
        `${identity.name} auth ${account.index}`,
      );
      const challenge = canonicalBase64url32(
        account.authentication.rawChallengeBase64url,
        `${identity.name} challenge ${account.index}`,
      );
      assert.equal(
        hex(challenge),
        hex(range((identityIndex * 2 + account.index) * 0x20)),
        `${identity.name} challenge literal range`,
      );
      assertEd25519(publicKey, challenge, account.authentication.signatureHex, `${identity.name} account ${account.index}`);
      assert.equal(Object.hasOwn(account, 'assetReviewApproval'), false);
      assert.equal(Object.hasOwn(account, 'contactEncryption'), false);
    }
  }

  exactKeys(vectors.leadingZeroFingerprint, [
    'accountIndex', 'accountXpub', 'peerId', 'fingerprint',
  ], 'leading-zero fingerprint');
  assert.deepEqual(vectors.leadingZeroFingerprint, {
    accountIndex: 1,
    accountXpub: 'xpub6BsrjbAKk2fyj16rqvwst2yh42rwfW3qmSg4nz6dPhRWWTop133fAdzRioTMK1KKk9HVLs3cYvsrxeQnwNuPH4kN8Wj3GhfeAC5GnwhGDan',
    peerId: '16Uiu2HAmRsk99krNTSoMYhNdoVsA2751NDZcwkS8qtW178iJCK4b',
    fingerprint: '57f94879',
  });
  exactKeys(vectors.validationCases, ['username', 'password', 'identityImport'], 'validation cases');
  assert.equal(vectors.validationCases.username.length, 14, 'username validation count');
  assert.equal(vectors.validationCases.password.length, 40, 'password validation count');
  assert.equal(vectors.validationCases.identityImport.length, 15, 'identity import count');
  for (const row of vectors.validationCases.username) {
    exactKeys(row, [
      'name', 'inputEncoding', 'inputHex', 'accepted', 'canonicalUsername', 'error',
    ], `username validation ${row.name}`);
  }
  for (const row of vectors.validationCases.password) {
    exactKeys(row, [
      'name', 'inputEncoding', 'inputHex', 'accepted', 'seedHex', 'error',
    ], `password validation ${row.name}`);
  }
  for (const row of vectors.validationCases.identityImport) {
    exactKeys(row, [
      'name', 'identityScheme', 'seedProfile', 'accountIndex', 'accountPath',
      'authenticationPath', 'contactEncryptionPath', 'assetReviewApprovalPath',
      'signatureProfile', 'accepted', 'error',
    ], `identity import ${row.name}`);
  }
  assert.deepEqual(vectors.validationCases.username, expectedUsernameCases());
  assert.deepEqual(vectors.validationCases.password, expectedPasswordCases());
  assert.deepEqual(vectors.validationCases.identityImport, expectedIdentityImports());
  for (const row of vectors.operationMatrix) {
    exactKeys(row, [
      'identityScheme', 'seedProfile', 'rawV1', 'jcsV2',
      'authorityActivation', 'decision',
    ], `operation matrix ${row.identityScheme}`);
  }
  assert.deepEqual(vectors.operationMatrix, [
    { identityScheme: IDENTITY_SCHEME, seedProfile: PASSWORD_PROFILE, rawV1: false, jcsV2: true, authorityActivation: true, decision: true },
    { identityScheme: 'sdn-fast-password-auth-v1-legacy', seedProfile: 'password-fast-v1-legacy', rawV1: true, jcsV2: false, authorityActivation: false, decision: false },
    { identityScheme: 'sdn-bip39-auth-v1-legacy', seedProfile: 'bip39-mnemonic-v1-legacy', rawV1: true, jcsV2: false, authorityActivation: false, decision: false },
  ]);
  return vectors;
}

const expectedCanonicalCases = new Map([
  ['auth-jcs-v2-password-account-0', ['d60302263a3df76a5e6d2b26603f1c8f782af0e14651f8148df55ed50238821f', '8b73c59a4bcd1a04d98942857016b0a7a4f7461416a810713fe2ed6db9d13e7deab501e613519f2290f199571a54af56a1c84b6475ae1a845130178b93770905']],
  ['auth-jcs-v2-password-account-1', ['f48a08889a71ea1cb14771bdbc78f0ddd7cf4c5506669ec416841e3931357cf7', 'd904862fded80a90793c4a5b2610105bf6d6109da49c085bdfee34d0338a6313b65d0e1f0db2c24d401b8ce9501432288d4165885aad74827103b2f887ca7e05']],
  ['asset-authority-activation-account-0', ['3df7721fe944aba327f7288861466fc033c1f95c4ddfd456d387804ca7743dda', 'dc98b9e9fff436e595afed4b66038f44bac475e387321ce3e4f2290e84ee09fb9297546300e4e473bce28dd830f42a8632b034b29152e700dadba12adef3ce0a']],
  ['asset-decision-approve-account-0', ['66d669400f9a2f61f9a017409a7ddd8a53f416bf71beb05f5f62d8202a587d18', '4e7743ae7b605316faa819bf2f3b2afae9d22575f9d7187554476d8b3fb9052a0ab42f829696492a7dc1e147f30c8ad4c07142293ab61d4f2bff9abf3ccaeb0e']],
  ['asset-decision-disapprove-account-0', ['ec2a61462a1d560e1e4f7f8d17afb8a2857d6e12e3d0b63432dd65eedf614602', '61f4bb58cfc76b54c6736f3922bbfef15342c9b9b197d16ded07725916ce02f192eedb301e54570ce1a0de1198241ebda05d481d00e307292c24507f176d6f02']],
]);

function verifyCanonicalCase(testCase, envelope, publicKey, label) {
  assert.equal(testCase.canonicalEnvelope, jcs(envelope), `${label} canonical envelope`);
  scanJsonNoDuplicates(testCase.canonicalEnvelope);
  assert.equal(jcs(JSON.parse(testCase.canonicalEnvelope)), testCase.canonicalEnvelope, `${label} inner canonical bytes`);
  const digest = sha256(utf8(testCase.canonicalEnvelope));
  assert.equal(hex(digest), testCase.signedDigestSha256, `${label} signed digest`);
  assertEd25519(publicKey, digest, testCase.signatureHex, label);
  assert.deepEqual(
    [testCase.signedDigestSha256, testCase.signatureHex],
    expectedCanonicalCases.get(testCase.name),
    `${label} reviewed literal`,
  );
}

function verifyOperationWire(vectors) {
  const wire = parseJsonFixture('test/fixtures/sdn-operation-wire-v1.json');
  exactKeys(wire, [
    'schemaVersion', 'authenticationCases', 'authorityActivationCases', 'decisionCases',
  ], 'operation wire');
  assert.equal(wire.schemaVersion, 1);
  assert.deepEqual(
    wire.authenticationCases.map((row) => row.name),
    [
      'auth-raw-v1-legacy-fast-account-0',
      'auth-raw-v1-legacy-fast-account-1',
      'auth-raw-v1-legacy-mnemonic-account-0',
      'auth-raw-v1-legacy-mnemonic-account-1',
      'auth-jcs-v2-password-account-0',
      'auth-jcs-v2-password-account-1',
    ],
  );
  assert.equal(wire.authorityActivationCases.length, 1);
  assert.equal(wire.authorityActivationCases[0].name, 'asset-authority-activation-account-0');
  assert.deepEqual(
    wire.decisionCases.map((row) => row.name),
    ['asset-decision-approve-account-0', 'asset-decision-disapprove-account-0'],
  );

  for (let index = 0; index < 4; index += 1) {
    const testCase = wire.authenticationCases[index];
    exactKeys(testCase, [
      'accountIndex', 'accountXpub', 'authenticationKeyId',
      'authenticationPublicKeyHex', 'canonicalEnvelope', 'identityScheme',
      'name', 'operation', 'request', 'seedProfile', 'signatureHex',
      'signatureProfile', 'signedDigestSha256',
    ], testCase.name);
    exactKeys(testCase.request, ['challengeBase64url', 'protocolVersion'], `${testCase.name} request`);
    assert.equal(testCase.operation, 'sdn.auth.raw-challenge.v1');
    assert.equal(testCase.request.protocolVersion, 1);
    assert.equal(testCase.signatureProfile, RAW_SIGNATURE_PROFILE);
    assert.equal(testCase.canonicalEnvelope, '');
    assert.equal(testCase.signedDigestSha256, '');
    const identity = vectors.legacyIdentities[Math.floor(index / 2)];
    const account = identity.accounts[index % 2];
    assert.equal(testCase.accountIndex, account.index);
    assert.equal(testCase.accountXpub, identity.rootPublicIdentity.accountXpub);
    assert.equal(testCase.identityScheme, identity.identityScheme);
    assert.equal(testCase.seedProfile, identity.seedProfile);
    assert.equal(testCase.authenticationKeyId, account.authentication.keyId);
    assert.equal(testCase.authenticationPublicKeyHex, account.authentication.publicKeyHex);
    assert.equal(testCase.request.challengeBase64url, account.authentication.rawChallengeBase64url);
    assert.equal(testCase.signatureHex, account.authentication.signatureHex);
    const publicKey = assertKeyId(testCase.authenticationPublicKeyHex, testCase.authenticationKeyId, testCase.name);
    assertEd25519(
      publicKey,
      canonicalBase64url32(testCase.request.challengeBase64url, `${testCase.name} challenge`),
      testCase.signatureHex,
      testCase.name,
    );
  }

  for (let index = 4; index < 6; index += 1) {
    const testCase = wire.authenticationCases[index];
    exactKeys(testCase, [
      'accountIndex', 'accountXpub', 'authenticationKeyId',
      'authenticationPublicKeyHex', 'canonicalEnvelope', 'identityScheme',
      'name', 'operation', 'request', 'registryBinding', 'seedProfile',
      'signatureHex', 'signatureProfile', 'signedDigestSha256',
    ], testCase.name);
    exactKeys(testCase.request, [
      'audience', 'challengeBase64url', 'expiresAt', 'issuedAt', 'nonce', 'protocolVersion',
    ], `${testCase.name} request`);
    exactKeys(testCase.registryBinding, ['clientId', 'requestOrigin'], `${testCase.name} binding`);
    const account = vectors.newIdentity.accounts[index - 4];
    assert.equal(testCase.accountIndex, account.index);
    assert.equal(testCase.accountXpub, account.accountXpub);
    assert.equal(testCase.authenticationKeyId, account.authentication.keyId);
    assert.equal(testCase.authenticationPublicKeyHex, account.authentication.publicKeyHex);
    assert.equal(testCase.identityScheme, IDENTITY_SCHEME);
    assert.equal(testCase.seedProfile, PASSWORD_PROFILE);
    assert.equal(testCase.operation, 'sdn.auth.jcs-envelope.v2');
    assert.equal(testCase.signatureProfile, SIGNATURE_PROFILE);
    assert.deepEqual(testCase.registryBinding, { clientId: AUTH_CLIENT, requestOrigin: AUTH_ORIGIN });
    const challenge = canonicalBase64url32(testCase.request.challengeBase64url, `${testCase.name} challenge`);
    assert.equal(testCase.request.audience, AUTH_AUDIENCE);
    assert.equal(testCase.request.protocolVersion, 2);
    lowerHex(testCase.request.nonce, 32, `${testCase.name} nonce`);
    const envelope = {
      audience: testCase.request.audience,
      challengeSha256: sha256Hex(challenge),
      clientId: AUTH_CLIENT,
      expiresAt: testCase.request.expiresAt,
      identityScheme: testCase.identityScheme,
      issuedAt: testCase.request.issuedAt,
      keyId: testCase.authenticationKeyId,
      kind: 'sdn-login',
      nonce: testCase.request.nonce,
      protocolVersion: 2,
      requestOrigin: AUTH_ORIGIN,
      signatureProfile: SIGNATURE_PROFILE,
    };
    assert.equal(Object.keys(envelope).length, 12);
    const publicKey = assertKeyId(testCase.authenticationPublicKeyHex, testCase.authenticationKeyId, testCase.name);
    verifyCanonicalCase(testCase, envelope, publicKey, testCase.name);
  }

  const activation = wire.authorityActivationCases[0];
  exactKeys(activation, [
    'accountIndex', 'accountXpub', 'approvalKeyId', 'approvalPublicKeyHex',
    'canonicalEnvelope', 'identityScheme', 'name', 'operation', 'request',
    'seedProfile', 'signatureHex', 'signatureProfile', 'signedDigestSha256',
  ], activation.name);
  exactKeys(activation.request, [
    'audience', 'clientId', 'expiresAt', 'identityScheme', 'issuedAt', 'keyId',
    'nonce', 'protocolVersion', 'publicKeyHex', 'purpose', 'requestOrigin',
    'serviceInstance', 'signatureProfile',
  ], 'activation request');
  const approval = vectors.newIdentity.accounts[0].assetReviewApproval;
  assert.equal(activation.accountIndex, 0);
  assert.equal(activation.accountXpub, vectors.newIdentity.accounts[0].accountXpub);
  assert.equal(activation.approvalKeyId, approval.keyId);
  assert.equal(activation.approvalPublicKeyHex, approval.publicKeyHex);
  assert.equal(activation.identityScheme, IDENTITY_SCHEME);
  assert.equal(activation.seedProfile, PASSWORD_PROFILE);
  assert.equal(activation.operation, 'sdn.asset-review.authority-activation.v1');
  assert.equal(activation.signatureProfile, SIGNATURE_PROFILE);
  assert.deepEqual(activation.request, {
    audience: AUTHORITY_AUDIENCE,
    clientId: REVIEW_CLIENT,
    expiresAt: '2026-07-20T22:05:00.000Z',
    identityScheme: IDENTITY_SCHEME,
    issuedAt: '2026-07-20T22:00:00.000Z',
    keyId: approval.keyId,
    nonce: hex(range(0)),
    protocolVersion: 1,
    publicKeyHex: approval.publicKeyHex,
    purpose: 'asset-review-authority-activation',
    requestOrigin: REVIEW_ORIGIN,
    serviceInstance: SERVICE_INSTANCE,
    signatureProfile: SIGNATURE_PROFILE,
  });
  const activationEnvelope = {
    ...activation.request,
    kind: 'asset-review-authority-activation',
  };
  assert.equal(Object.keys(activationEnvelope).length, 14);
  const approvalPublicKey = assertKeyId(activation.approvalPublicKeyHex, activation.approvalKeyId, activation.name);
  verifyCanonicalCase(activation, activationEnvelope, approvalPublicKey, activation.name);

  for (const decision of wire.decisionCases) {
    exactKeys(decision, [
      'accountIndex', 'accountXpub', 'approvalKeyId', 'approvalPublicKeyHex',
      'canonicalEnvelope', 'identityScheme', 'name', 'operation', 'request',
      'seedProfile', 'signatureHex', 'signatureProfile', 'signedDigestSha256',
    ], decision.name);
    const isApprove = decision.request.decision === 'approve';
    exactKeys(decision.request, isApprove
      ? ['audience', 'candidateKey', 'challengeId', 'clientId', 'decision', 'expiresAt', 'issuedAt', 'metadataSha256', 'modelBytes', 'modelCid', 'modelSha256', 'nonce', 'note', 'previousDecisionHead', 'protocolVersion', 'requestOrigin', 'reviewedTransform']
      : ['audience', 'candidateKey', 'challengeId', 'clientId', 'decision', 'expiresAt', 'issuedAt', 'metadataSha256', 'modelBytes', 'modelCid', 'modelSha256', 'nonce', 'previousDecisionHead', 'protocolVersion', 'reason', 'requestOrigin'],
    `${decision.name} request`);
    if (isApprove) {
      exactKeys(decision.request.reviewedTransform, [
        'translation', 'rotation', 'scale', 'sourceUnits',
        'metersPerSourceUnit', 'upAxis',
      ], `${decision.name} reviewed transform`);
      assert.deepEqual(
        decision.request.reviewedTransform,
        expectedProtocol.boundaryVectors.baseTransform,
        `${decision.name} reviewed transform literal`,
      );
    }
    assert.equal(decision.operation, 'sdn.asset-review.decision.v1');
    assert.equal(decision.accountIndex, 0);
    assert.equal(decision.accountXpub, vectors.newIdentity.accounts[0].accountXpub);
    assert.equal(decision.approvalKeyId, approval.keyId);
    assert.equal(decision.approvalPublicKeyHex, approval.publicKeyHex);
    assert.equal(decision.identityScheme, IDENTITY_SCHEME);
    assert.equal(decision.seedProfile, PASSWORD_PROFILE);
    assert.equal(decision.signatureProfile, SIGNATURE_PROFILE);
    assert.equal(decision.request.audience, REVIEW_AUDIENCE);
    assert.equal(decision.request.clientId, REVIEW_CLIENT);
    assert.equal(decision.request.requestOrigin, REVIEW_ORIGIN);
    assert.equal(decision.request.protocolVersion, 1);
    lowerHex(decision.request.challengeId, 32, `${decision.name} challenge ID`);
    lowerHex(decision.request.nonce, 32, `${decision.name} nonce`);
    lowerHex(decision.request.modelSha256, 32, `${decision.name} model hash`);
    lowerHex(decision.request.metadataSha256, 32, `${decision.name} metadata hash`);
    const envelope = {
      ...decision.request,
      identityScheme: IDENTITY_SCHEME,
      keyId: approval.keyId,
      kind: 'asset-review-attestation',
      purpose: 'asset-review-approval',
      signatureProfile: SIGNATURE_PROFILE,
    };
    assert.equal(Object.keys(envelope).length, isApprove ? 22 : 21);
    verifyCanonicalCase(decision, envelope, approvalPublicKey, decision.name);
  }
  const approve = wire.decisionCases[0];
  const disapprove = wire.decisionCases[1];
  assert.equal(approve.request.note, 'Synthetic fixture approval.');
  assert.equal(approve.request.previousDecisionHead, null);
  assert.equal(disapprove.request.reason, 'Synthetic fixture rejection.');
  const approveHead = sha256Hex(Buffer.concat([
    utf8('sdn-asset-review-attestation-record-v1\0'),
    unhex(approve.signedDigestSha256),
  ]));
  assert.equal(approveHead, '5bf299ed6cc14cefe075bad165cf1e02992903f976202e87772905385df87dda');
  assert.equal(disapprove.request.previousDecisionHead, approveHead);
}

const expectedProtocol = {
  schemaVersion: 1,
  reviewedTransform: {
    metersPerSourceUnit: { cm: 0.01, km: 1000, m: 1, mm: 0.001 },
    quaternionNormTolerance: 0.000001,
    scaleComponentExclusiveMin: 0,
    scaleComponentInclusiveMax: 1000000,
    translationComponentAbsMax: 1000000,
    upAxes: ['X_UP', 'Y_UP', 'Z_UP'],
  },
  boundaryVectors: {
    baseTransform: {
      translation: [0, 0, 0], rotation: [0, 0, 0, 1], scale: [1, 1, 1],
      sourceUnits: 'm', metersPerSourceUnit: 1, upAxis: 'Y_UP',
    },
    translationComponents: [
      { name: 'below-min', value: -1000000.0000000001, expected: 'reject' },
      { name: 'min', value: -1000000, expected: 'accept' },
      { name: 'max', value: 1000000, expected: 'accept' },
      { name: 'above-max', value: 1000000.0000000001, expected: 'reject' },
    ],
    scaleComponents: [
      { name: 'negative-min-subnormal', value: -5e-324, expected: 'reject' },
      { name: 'zero', value: 0, expected: 'reject' },
      { name: 'min-positive-subnormal', value: 5e-324, expected: 'accept' },
      { name: 'max', value: 1000000, expected: 'accept' },
      { name: 'above-max', value: 1000000.0000000001, expected: 'reject' },
    ],
    rotations: [
      { name: 'below-negative-tolerance', value: [0, 0, 0, 0.999999], expected: 'reject' },
      { name: 'negative-tolerance', value: [0, 0, 0, 0.9999990000000001], expected: 'accept' },
      { name: 'positive-tolerance', value: [0, 0, 0, 1.000001], expected: 'accept' },
      { name: 'above-positive-tolerance', value: [0, 0, 0, 1.0000010000000001], expected: 'reject' },
    ],
    unitPairs: [
      { name: 'meters', sourceUnits: 'm', metersPerSourceUnit: 1, expected: 'accept' },
      { name: 'centimeters', sourceUnits: 'cm', metersPerSourceUnit: 0.01, expected: 'accept' },
      { name: 'millimeters', sourceUnits: 'mm', metersPerSourceUnit: 0.001, expected: 'accept' },
      { name: 'kilometers', sourceUnits: 'km', metersPerSourceUnit: 1000, expected: 'accept' },
      { name: 'wrong-meters', sourceUnits: 'm', metersPerSourceUnit: 0.01, expected: 'reject' },
      { name: 'unsupported-feet', sourceUnits: 'ft', metersPerSourceUnit: 0.3048, expected: 'reject' },
    ],
    upAxes: [
      { name: 'x-up', value: 'X_UP', expected: 'accept' },
      { name: 'y-up', value: 'Y_UP', expected: 'accept' },
      { name: 'z-up', value: 'Z_UP', expected: 'accept' },
      { name: 'invalid-w-up', value: 'W_UP', expected: 'reject' },
    ],
  },
};

function validateTransform(transform, policy) {
  if (!transform || typeof transform !== 'object') return false;
  if (!Array.isArray(transform.translation) || transform.translation.length !== 3) return false;
  if (!transform.translation.every((value) => Number.isFinite(value)
    && Math.abs(value) <= policy.translationComponentAbsMax)) return false;
  if (!Array.isArray(transform.scale) || transform.scale.length !== 3) return false;
  if (!transform.scale.every((value) => Number.isFinite(value)
    && value > policy.scaleComponentExclusiveMin
    && value <= policy.scaleComponentInclusiveMax)) return false;
  if (!Array.isArray(transform.rotation) || transform.rotation.length !== 4
    || !transform.rotation.every(Number.isFinite)) return false;
  const norm = Math.hypot(...transform.rotation);
  if (Math.abs(norm - 1) > policy.quaternionNormTolerance) return false;
  if (!Object.hasOwn(policy.metersPerSourceUnit, transform.sourceUnits)) return false;
  if (transform.metersPerSourceUnit !== policy.metersPerSourceUnit[transform.sourceUnits]) return false;
  return policy.upAxes.includes(transform.upAxis);
}

function verifyProtocol() {
  const protocol = parseJsonFixture('release/protocol/asset-review-v1.json');
  assert.deepEqual(protocol, expectedProtocol, 'asset review protocol literal');
  exactKeys(protocol, ['schemaVersion', 'reviewedTransform', 'boundaryVectors'], 'asset protocol');
  exactKeys(protocol.reviewedTransform, [
    'metersPerSourceUnit', 'quaternionNormTolerance',
    'scaleComponentExclusiveMin', 'scaleComponentInclusiveMax',
    'translationComponentAbsMax', 'upAxes',
  ], 'reviewed transform policy');
  exactKeys(
    protocol.reviewedTransform.metersPerSourceUnit,
    ['cm', 'km', 'm', 'mm'],
    'reviewed transform unit map',
  );
  exactKeys(protocol.boundaryVectors, [
    'baseTransform', 'translationComponents', 'scaleComponents', 'rotations',
    'unitPairs', 'upAxes',
  ], 'boundary vectors');
  exactKeys(protocol.boundaryVectors.baseTransform, [
    'translation', 'rotation', 'scale', 'sourceUnits',
    'metersPerSourceUnit', 'upAxis',
  ], 'base transform');
  assert(validateTransform(protocol.boundaryVectors.baseTransform, protocol.reviewedTransform));
  for (const row of protocol.boundaryVectors.translationComponents) {
    exactKeys(row, ['name', 'value', 'expected'], `translation ${row.name}`);
    const transform = structuredClone(protocol.boundaryVectors.baseTransform);
    transform.translation[0] = row.value;
    assert.equal(validateTransform(transform, protocol.reviewedTransform), row.expected === 'accept', row.name);
  }
  for (const row of protocol.boundaryVectors.scaleComponents) {
    exactKeys(row, ['name', 'value', 'expected'], `scale ${row.name}`);
    const transform = structuredClone(protocol.boundaryVectors.baseTransform);
    transform.scale[0] = row.value;
    assert.equal(validateTransform(transform, protocol.reviewedTransform), row.expected === 'accept', row.name);
  }
  for (const row of protocol.boundaryVectors.rotations) {
    exactKeys(row, ['name', 'value', 'expected'], `rotation ${row.name}`);
    const transform = structuredClone(protocol.boundaryVectors.baseTransform);
    transform.rotation = row.value;
    assert.equal(validateTransform(transform, protocol.reviewedTransform), row.expected === 'accept', row.name);
  }
  for (const row of protocol.boundaryVectors.unitPairs) {
    exactKeys(row, ['name', 'sourceUnits', 'metersPerSourceUnit', 'expected'], `units ${row.name}`);
    const transform = structuredClone(protocol.boundaryVectors.baseTransform);
    transform.sourceUnits = row.sourceUnits;
    transform.metersPerSourceUnit = row.metersPerSourceUnit;
    assert.equal(validateTransform(transform, protocol.reviewedTransform), row.expected === 'accept', row.name);
  }
  for (const row of protocol.boundaryVectors.upAxes) {
    exactKeys(row, ['name', 'value', 'expected'], `axis ${row.name}`);
    const transform = structuredClone(protocol.boundaryVectors.baseTransform);
    transform.upAxis = row.value;
    assert.equal(validateTransform(transform, protocol.reviewedTransform), row.expected === 'accept', row.name);
  }
  return protocol;
}

try {
  verifyNoncharacterRejection();
  verifyIntegrity();
  verifySources();
  const vectors = verifyWalletVectors();
  verifyOperationWire(vectors);
  verifyProtocol();
  console.log(
    'PASS: seven immutable fixture entries, 14/40/15 validation rows, and 6+1+2 operation cases verified',
  );
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exitCode = 1;
}
