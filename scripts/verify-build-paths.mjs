import { lstat, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const CANONICAL_OPENSSL_PREFIX = '/hd-wallet-build/openssl-3.0.9';
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const WASM_MAGIC = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
const OPENSSL_BUILD_PATH_MARKER = '/hd-wallet-build/openssl-';
const OPENSSL_BUILD_PATH_TOKEN = /\/hd-wallet-build\/openssl-[A-Za-z0-9._/-]+/gu;
const NON_PORTABLE_POSIX_ROOT = /\/(?:Users|Volumes|__w|builds?|codebuild|home|mnt|opt|private|runner|tmp|var|workspaces?)(?:\/|$)/u;
const NON_PORTABLE_WINDOWS_ROOT = /(?:[A-Za-z]:\\|(?:^|[^A-Za-z0-9%])[A-Za-z]:\/|\\\\[A-Za-z0-9._-]+\\)/u;

function fail(message) {
  throw new Error(`build path verification failed: ${message}`);
}

function printableStrings(bytes) {
  const strings = [];
  let start = -1;
  for (let index = 0; index <= bytes.byteLength; index += 1) {
    const byte = index < bytes.byteLength ? bytes[index] : 0;
    if (byte >= 0x20 && byte <= 0x7e) {
      if (start === -1) start = index;
    } else if (start !== -1) {
      if (index - start >= 8) strings.push(bytes.subarray(start, index).toString('ascii'));
      start = -1;
    }
  }
  return strings;
}

function inspectOpenSslBuildPaths(value) {
  let canonicalPrefixSeen = false;
  let offset = 0;
  while (offset < value.length) {
    const marker = value.indexOf(OPENSSL_BUILD_PATH_MARKER, offset);
    if (marker === -1) break;
    const exactPrefix = value.startsWith(CANONICAL_OPENSSL_PREFIX, marker);
    const prefixBoundary = value[marker + CANONICAL_OPENSSL_PREFIX.length];
    const token = /^\/[A-Za-z0-9._/-]+/u.exec(value.slice(marker))?.[0] ?? '';
    const tokenBoundary = value[marker + token.length];
    const isCanonical = token === CANONICAL_OPENSSL_PREFIX
      || token.startsWith(`${CANONICAL_OPENSSL_PREFIX}/`);
    const segments = token.split('/').slice(1);
    const hasUnsafeSegment = segments.some((segment) => (
      segment === '' || segment === '.' || segment === '..'
    ));
    if (
      !exactPrefix
      || (prefixBoundary !== undefined && prefixBoundary !== '/')
      || !isCanonical
      || hasUnsafeSegment
      || (tokenBoundary !== undefined && tokenBoundary !== '"' && tokenBoundary !== "'")
    ) {
      return { canonicalPrefixSeen, invalid: true };
    }
    canonicalPrefixSeen = true;
    offset = marker + token.length;
  }
  return { canonicalPrefixSeen, invalid: false };
}

export function assertPortableBuildBytes(bytes, label, { forbiddenRoots = [] } = {}) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    fail(`${label} is not a byte sequence`);
  }
  const normalized = Buffer.from(bytes);
  if (normalized.byteLength === 0 || normalized.byteLength > MAX_ARTIFACT_BYTES) {
    fail(`${label} is empty or oversized`);
  }
  let canonicalPrefixSeen = false;
  for (const value of printableStrings(normalized)) {
    const openSslPaths = inspectOpenSslBuildPaths(value);
    canonicalPrefixSeen ||= openSslPaths.canonicalPrefixSeen;
    const hostPathValue = value.replace(OPENSSL_BUILD_PATH_TOKEN, '');
    const hasForbiddenRoot = forbiddenRoots.some((root) => root.length > 1 && value.includes(root));
    if (openSslPaths.invalid
        || hasForbiddenRoot
        || /hd-wallet-openssl\./u.test(value)
        || NON_PORTABLE_POSIX_ROOT.test(hostPathValue)
        || NON_PORTABLE_WINDOWS_ROOT.test(hostPathValue)) {
      fail(`${label} contains a non-portable build path`);
    }
  }
  if (!canonicalPrefixSeen) fail(`${label} does not contain the canonical OpenSSL prefix`);
  return true;
}

export function decodeInlineWasm(source) {
  if (typeof source !== 'string') fail('inline Emscripten artifact is not text');
  const modules = [];
  for (const match of source.matchAll(
    /data:application\/octet-stream;base64,([A-Za-z0-9+/]+={0,2})/gu,
  )) {
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.subarray(0, WASM_MAGIC.byteLength).equals(WASM_MAGIC)) modules.push(bytes);
  }
  if (modules.length !== 1) fail('inline artifact must contain exactly one embedded WebAssembly module');
  return modules[0];
}

async function readBoundedRegularFile(path) {
  const metadata = await lstat(path).catch(() => null);
  if (!metadata?.isFile() || metadata.isSymbolicLink()
      || metadata.size <= 0 || metadata.size > MAX_ARTIFACT_BYTES) {
    fail(`${path} is not a bounded regular build artifact`);
  }
  return readFile(path);
}

async function main() {
  if (process.argv.length !== 2) fail('verifier takes no arguments');
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const temporaryRoot = await realpath(tmpdir());
  const forbiddenRoots = [repositoryRoot, temporaryRoot];
  const binaryPaths = [
    'openssl-fips/dist/lib/libcrypto.a',
    'wasm/dist/hd-wallet.wasm',
    'wasm/dist/hd-wallet-wasi.wasm',
  ];
  const fipsArchive = join(repositoryRoot, 'openssl-fips/dist/lib/fips.a');
  if ((await lstat(fipsArchive).catch(() => null))?.isFile()) {
    binaryPaths.push('openssl-fips/dist/lib/fips.a');
  }
  for (const relativePath of binaryPaths) {
    const bytes = await readBoundedRegularFile(join(repositoryRoot, relativePath));
    assertPortableBuildBytes(bytes, relativePath, { forbiddenRoots });
  }
  const inlinePath = join(repositoryRoot, 'wasm/dist/hd-wallet.js');
  const inlineSource = (await readBoundedRegularFile(inlinePath)).toString('utf8');
  assertPortableBuildBytes(decodeInlineWasm(inlineSource), 'wasm/dist/hd-wallet.js embedded WASM', {
    forbiddenRoots,
  });
  process.stdout.write(`${JSON.stringify({
    canonicalOpenSslPrefix: CANONICAL_OPENSSL_PREFIX,
    files: binaryPaths.length + 1,
    status: 'verified',
  })}\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'build path verification failed'}\n`);
    process.exitCode = 1;
  });
}
