import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepositoryRoot = path.resolve(path.dirname(scriptPath), '..');
const ignoredFiles = new Set([
  'scripts/test-no-live-test-fetches.mjs',
  'scripts/test-no-live-test-fetches.test.mjs',
  'scripts/verify-fixtures.mjs',
]);
const ignoredDirectories = new Set([
  '.git',
  'build',
  'build-wasi',
  'dist',
  'node_modules',
  'target',
]);
const inspectedRoots = ['scripts', 'test', 'wasm/test', 'wallet-ui/test'];
const inspectedExtensions = new Set([
  '.bash', '.c', '.cc', '.cmake', '.cpp', '.cxx', '.dart', '.go', '.h', '.hh',
  '.hpp', '.htm', '.html', '.java', '.js', '.jsx', '.kts', '.kt', '.mjs', '.cjs',
  '.php', '.py', '.rb', '.rs', '.sh', '.swift', '.ts', '.tsx', '.yaml', '.yml', '.zsh',
]);
const acquisitionPatterns = [
  ['raw GitHub test data URL', /raw\.githubusercontent\.com/],
  [
    'curl invocation',
    /(?:^|[;&|()]|\bthen\b|\bdo\b)\s*(?:command\s+|env(?:\s+[A-Za-z_]\w*=\S+)*\s+|sudo\s+)?curl\b/m,
  ],
  [
    'wget invocation',
    /(?:^|[;&|()]|\bthen\b|\bdo\b)\s*(?:command\s+|env(?:\s+[A-Za-z_]\w*=\S+)*\s+|sudo\s+)?wget\b/m,
  ],
  ['JavaScript fetch from a network URL', /\bfetch\s*\(\s*['"`]https?:\/\//],
  ['Node HTTP request', /\bhttps?\s*\.\s*(?:get|request)\s*\([^)]*['"`]https?:\/\//s],
  [
    'Go HTTP request',
    /\bhttps?\s*\.\s*(?:Get|Post|Head|NewRequest|NewRequestWithContext)\s*\([\s\S]{0,300}?['"`]https?:\/\//,
  ],
  [
    'Rust HTTP request',
    /\b(?:reqwest(?:::[A-Za-z_]\w*)*|ureq)::(?:get|post|request)\s*\(\s*['"`]https?:\/\//,
  ],
  [
    'Dart HTTP request',
    /\b(?:getUrl|postUrl|openUrl)\s*\([\s\S]{0,300}?['"`]https?:\/\//,
  ],
  [
    'Python HTTP request',
    /\b(?:(?:requests|httpx|aiohttp)\s*\.\s*(?:get|post|request)|(?:urllib\s*\.\s*request\s*\.\s*)?urlopen)\s*\([\s\S]{0,300}?['"`]https?:\/\//,
  ],
  ['HTML network resource', /\b(?:src|href)\s*=\s*['"]https?:\/\//i],
  ['CMake file download', /\bfile\s*\(\s*DOWNLOAD\b/i],
];

function relative(repositoryRoot, filePath) {
  return path.relative(repositoryRoot, filePath).split(path.sep).join('/');
}

function listFiles(rootPath) {
  if (!existsSync(rootPath)) return [];
  if (!statSync(rootPath).isDirectory()) return [rootPath];
  return readdirSync(rootPath, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) return [];
    const child = path.join(rootPath, entry.name);
    if (entry.isDirectory()) return listFiles(child);
    return entry.isFile() ? [child] : [];
  });
}

function inspectBody(file, body) {
  const failures = [];
  for (const [description, pattern] of acquisitionPatterns) {
    if (pattern.test(body)) failures.push(`${file}: contains ${description}`);
  }
  return failures;
}

function findPackageManifests(repositoryRoot) {
  return listFiles(repositoryRoot).filter((filePath) => path.basename(filePath) === 'package.json');
}

export function scanRepository(repositoryRoot = defaultRepositoryRoot) {
  const failures = [];
  const cmakePath = path.join(repositoryRoot, 'CMakeLists.txt');
  if (!existsSync(cmakePath)) {
    failures.push('CMakeLists.txt: file is missing');
  } else {
    const cmake = readFileSync(cmakePath, 'utf8');
    const nativeTestsStart = cmake.indexOf('# Tests (native only)');
    const nativeTestsEnd = cmake.indexOf('# Documentation', nativeTestsStart);
    if (nativeTestsStart === -1 || nativeTestsEnd === -1) {
      failures.push('CMakeLists.txt: native test registration boundaries are missing');
    } else {
      const nativeTestRegistration = cmake.slice(nativeTestsStart, nativeTestsEnd);
      failures.push(...inspectBody('CMakeLists.txt', nativeTestRegistration));
      if (/\bFetchContent_(?:Declare|MakeAvailable)\s*\(/.test(nativeTestRegistration)) {
        failures.push('CMakeLists.txt: native tests acquire data through FetchContent');
      }
    }
  }

  for (const inspectedRoot of inspectedRoots) {
    const absoluteRoot = path.join(repositoryRoot, inspectedRoot);
    for (const filePath of listFiles(absoluteRoot)) {
      const file = relative(repositoryRoot, filePath);
      if (ignoredFiles.has(file) || !inspectedExtensions.has(path.extname(filePath))) {
        continue;
      }
      failures.push(...inspectBody(file, readFileSync(filePath, 'utf8')));
    }
  }

  for (const manifestPath of findPackageManifests(repositoryRoot)) {
    const file = relative(repositoryRoot, manifestPath);
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } catch (error) {
      failures.push(`${file}: invalid JSON (${error.message})`);
      continue;
    }
    for (const [name, command] of Object.entries(manifest.scripts ?? {})) {
      if (!/^(?:pre|post)?test(?::|$)/.test(name) || typeof command !== 'string') continue;
      failures.push(...inspectBody(`${file}#scripts.${name}`, command));
    }
  }

  return failures;
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  const failures = scanRepository();
  if (failures.length > 0) {
    console.error(`FAIL: live test-data acquisition found\n${failures.join('\n')}`);
    process.exitCode = 1;
  } else {
    console.log('PASS: tests and test helpers use committed local data only');
  }
}
