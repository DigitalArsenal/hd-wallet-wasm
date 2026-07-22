import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localCi = readFileSync(path.join(repositoryRoot, 'scripts/ci-local.sh'), 'utf8');
const hostedCi = readFileSync(path.join(repositoryRoot, '.github/workflows/build.yml'), 'utf8');
const publishCi = readFileSync(
  path.join(repositoryRoot, '.github/workflows/npm-publish.yml'),
  'utf8',
);
const cmake = readFileSync(path.join(repositoryRoot, 'CMakeLists.txt'), 'utf8');
const packageJson = JSON.parse(readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'));
const uiPackageJson = JSON.parse(
  readFileSync(path.join(repositoryRoot, 'wallet-ui/package.json'), 'utf8'),
);

const cryptoppSource = Object.freeze({
  commit: '843d74c7c97f9e19a615b8ff3c0ca06599ca501b',
  repository: 'https://github.com/weidai11/cryptopp.git',
});
const cryptoppCmakeSource = Object.freeze({
  commit: 'f815f6284684be6ab03af4b6c273359331c61241',
  sha256: '6ac4e8002b1167bb5393744e1f97a1207c39c9073fcff0efc1a43c0f0255edbe',
  url: 'https://github.com/abdes/cryptopp-cmake/archive/f815f6284684be6ab03af4b6c273359331c61241.tar.gz',
});

assert.match(
  cmake,
  /add_custom_command\(TARGET hd_wallet_wasm_npm POST_BUILD[\s\S]{0,300}?scripts\/stage-core-package\.mjs/u,
  'the canonical CMake package target must finish with deterministic typed staging',
);

for (const [label, workflow] of [
  ['hosted', hostedCi],
  ['publish', publishCi],
]) {
  assert.match(
    workflow,
    /uses: actions\/setup-node@a0853c24544627f65ddf259abe73b1d18a591444[\s\S]{0,120}?node-version: "24\.18\.0"/u,
    `${label} workflow must install exact Node before building`,
  );
  assert.match(workflow, /npm@11\.16\.0/u, `${label} workflow must install exact npm`);
  assert.match(workflow, /\.\/scripts\/ci-local\.sh/u, `${label} workflow must run the full local gate`);
  assert.match(workflow, /--emit-artifacts/u, `${label} workflow must use the release verifier`);
  assert.doesNotMatch(
    workflow,
    /cp\s+[^\n]*hd-wallet(?:-inline)?\.js\s+[^\n]*wasm\/dist/u,
    `${label} workflow must not manually replace CMake-staged JavaScript`,
  );
}

assert.match(localCi, /npm run build:release/u);
assert.match(localCi, /npm run test:packed/u);
assert.doesNotMatch(localCi, /\b(?:quick|native|wasm|npm)\)\s*$/mu);
assert.doesNotMatch(localCi, /cp\s+[^\n]*build[^\n]*wasm\/dist/u);
assert.match(packageJson.scripts?.['build:release'] ?? '', /npm run build:openssl-fips/u);
assert.match(packageJson.scripts?.['build:release'] ?? '', /npm run configure:wasm/u);
assert.match(packageJson.scripts?.['build:release'] ?? '', /npm run build:wallet-assets/u);
assert.equal(
  uiPackageJson.scripts?.test,
  'vitest run --no-file-parallelism',
  'UI test files must not race while rebuilding the shared dist directory',
);
assert.match(
  packageJson.scripts?.['configure:wasm'] ?? '',
  /emcmake cmake -B build-wasm[\s\S]*-DHD_WALLET_USE_OPENSSL=ON/u,
);
assert.match(
  cmake,
  /if\(EMSCRIPTEN\)[\s\S]{0,1100}?set\(CRYPTOPP_SOLARIS TRUE\)[\s\S]{0,120}?FetchContent_MakeAvailable\(cryptopp-cmake\)[\s\S]{0,80}?if\(EMSCRIPTEN\)[\s\S]{0,80}?unset\(CRYPTOPP_SOLARIS\)/u,
  'the Emscripten dependency must scope out bare SunCC compiler probes that dirty the source tree',
);

const emscriptenSection = cmake.slice(cmake.indexOf('if(HD_WALLET_BUILD_WASM OR EMSCRIPTEN)'));
assert.ok(emscriptenSection.length > 0, 'the Emscripten build section must exist');
assert.doesNotMatch(
  emscriptenSection,
  /\$<\$<CONFIG:Release>:-O3>/u,
  'the frozen Emscripten release must not use the size-inflating O3 profile',
);
assert.match(
  cmake,
  /target_compile_options\(cryptopp PRIVATE[\s\S]{0,160}?\$<\$<CONFIG:Release>:-Oz>[\s\S]{0,80}?\$<\$<CONFIG:Release>:-flto>/u,
  'Crypto++ must use the same size-optimized release profile as the wallet targets',
);
const cryptoppDeclaration = cmake.indexOf('FetchContent_Declare(\n    cryptopp\n');
const cryptoppCmakeDeclaration = cmake.indexOf('FetchContent_Declare(\n    cryptopp-cmake\n');
assert.ok(
  cryptoppDeclaration !== -1 && cryptoppDeclaration < cryptoppCmakeDeclaration,
  'the direct Crypto++ source pin must be declared before its CMake wrapper',
);
assert.ok(cmake.includes(cryptoppSource.repository), 'Crypto++ must use its reviewed upstream repository');
assert.match(
  cmake,
  new RegExp(`GIT_TAG\\s+${cryptoppSource.commit}[\\s\\S]{0,80}?GIT_SHALLOW\\s+FALSE`, 'u'),
  'Crypto++ must resolve the exact full source commit rather than a mutable tag',
);
assert.ok(
  cmake.includes(cryptoppCmakeSource.url),
  'Crypto++ CMake wrapper must use its immutable commit archive URL',
);
assert.ok(
  cmake.includes(`URL_HASH SHA256=${cryptoppCmakeSource.sha256}`),
  'Crypto++ CMake wrapper must verify its archive SHA-256',
);
assert.ok(
  cmake.includes(cryptoppCmakeSource.commit),
  'Crypto++ CMake wrapper must record its resolved source commit',
);
const cryptoppDependencySection = cmake.slice(
  cmake.indexOf('# Crypto++ Dependency'),
  cmake.indexOf('# OpenSSL FIPS Backend'),
);
assert.doesNotMatch(
  cryptoppDependencySection,
  /CRYPTOPP_8_9_0/u,
  'the Crypto++ dependency graph must not resolve a mutable named tag',
);
assert.deepEqual(
  [...cryptoppDependencySection.matchAll(/GIT_TAG[ \t]+([^\s#]+)/gu)]
    .map((match) => match[1]),
  [cryptoppSource.commit],
  'the Crypto++ dependency graph must contain only the reviewed full source commit',
);
for (const target of ['secp256k1_precomputed', 'secp256k1']) {
  assert.match(
    cmake,
    new RegExp(`target_compile_options\\(${target} PRIVATE[\\s\\S]{0,160}?\\$<\\$<CONFIG:Release>:-Oz>[\\s\\S]{0,80}?\\$<\\$<CONFIG:Release>:-flto>`, 'u'),
    `${target} must use the size-optimized release profile`,
  );
}
assert.ok(
  (emscriptenSection.match(/\$<\$<CONFIG:Release>:-Oz>/gu) ?? []).length >= 4,
  'every Emscripten wallet artifact must link with the size-optimized release profile',
);

for (const artifact of ['npm-tarballs', 'origin-service', 'wallet-release-report']) {
  assert.match(
    hostedCi,
    new RegExp(`uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02[\\s\\S]{0,160}?name: ${artifact}`, 'u'),
    `hosted CI must upload ${artifact}`,
  );
}

assert.doesNotMatch(publishCi, /actions\/download-artifact|actions\/cache|^\s*cache:/mu);
assert.doesNotMatch(publishCi, /npm\s+version/u);
assert.match(
  publishCi,
  /npm publish --provenance --tag "\$DIST_TAG" --access public "\$tarball"/u,
  'publication must consume the once-built verified tarball',
);
for (const packageName of ['hd-wallet-wasm', 'hd-wallet-ui']) {
  assert.ok(
    publishCi.includes(`$artifact_root/npm-tarballs/${packageName}-2.0.23.tgz`),
    `publish workflow must consume the exact ${packageName} tarball`,
  );
}

console.log('PASS: local and hosted release gates preserve canonical typed package staging');
