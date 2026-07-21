import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);

const ignoredFiles = new Set([
  'scripts/test-no-live-test-fetches.mjs',
  'scripts/verify-fixtures.mjs',
]);
const inspectedRoots = ['scripts', 'test', 'wasm/test', 'wallet-ui/test'];
const inspectedExtensions = new Set(['.cmake', '.cpp', '.h', '.js', '.mjs', '.sh']);
const acquisitionPatterns = [
  ['raw GitHub test data URL', /raw\.githubusercontent\.com/],
  ['curl invocation', /(^|[;&|]\s*|\$\()curl\b/m],
  ['wget invocation', /(^|[;&|]\s*|\$\()wget\b/m],
  ['JavaScript fetch from a network URL', /\bfetch\s*\(\s*['"`]https?:\/\//],
  ['Node HTTP request', /\bhttps?\s*\.\s*(?:get|request)\s*\(/],
  ['CMake file download', /\bfile\s*\(\s*DOWNLOAD\b/i],
];

function relative(filePath) {
  return path.relative(repositoryRoot, filePath).split(path.sep).join('/');
}

function listFiles(rootPath) {
  if (!statSync(rootPath).isDirectory()) return [rootPath];
  return readdirSync(rootPath, { withFileTypes: true }).flatMap((entry) => {
    const child = path.join(rootPath, entry.name);
    if (entry.isDirectory()) return listFiles(child);
    return entry.isFile() ? [child] : [];
  });
}

const failures = [];
const cmake = readFileSync(path.join(repositoryRoot, 'CMakeLists.txt'), 'utf8');
const nativeTestsStart = cmake.indexOf('# Tests (native only)');
const nativeTestsEnd = cmake.indexOf('# Documentation', nativeTestsStart);
if (nativeTestsStart === -1 || nativeTestsEnd === -1) {
  failures.push('CMakeLists.txt: native test registration boundaries are missing');
} else {
  const nativeTestRegistration = cmake.slice(nativeTestsStart, nativeTestsEnd);
  for (const [description, pattern] of acquisitionPatterns) {
    if (pattern.test(nativeTestRegistration)) {
      failures.push(`CMakeLists.txt: native tests contain ${description}`);
    }
  }
  if (/\bFetchContent_(?:Declare|MakeAvailable)\s*\(/.test(nativeTestRegistration)) {
    failures.push('CMakeLists.txt: native tests acquire data through FetchContent');
  }
}

for (const inspectedRoot of inspectedRoots) {
  const absoluteRoot = path.join(repositoryRoot, inspectedRoot);
  for (const filePath of listFiles(absoluteRoot)) {
    const file = relative(filePath);
    if (ignoredFiles.has(file) || !inspectedExtensions.has(path.extname(filePath))) {
      continue;
    }
    const body = readFileSync(filePath, 'utf8');
    for (const [description, pattern] of acquisitionPatterns) {
      if (pattern.test(body)) failures.push(`${file}: contains ${description}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL: live test-data acquisition found\n${failures.join('\n')}`);
  process.exitCode = 1;
} else {
  console.log('PASS: tests and test helpers use committed local data only');
}
