import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { access, readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import walletViteConfig from '../vite.config.js';

const walletUiDirectory = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const repositoryDirectory = resolve(walletUiDirectory, '..');
const distDirectory = join(walletUiDirectory, 'dist');

const STATIC_DIST_FILES = Object.freeze([
  'browser/sdn-wallet-callback.js',
  'browser/sdn-wallet-public-client.js',
  'browser/wallet-callback.html',
  'client/asset-review.d.ts',
  'client/asset-review.js',
  'client/callback.d.ts',
  'client/callback.js',
  'client/index.d.ts',
  'client/index.js',
  'client/sdn.d.ts',
  'client/sdn.js',
  'client/style.css',
  'client/types.d.ts',
  'compat/index.d.ts',
  'compat/index.js',
  'wallet-origin-host/index.html',
  'wallet-origin-host/integrity.json',
  'wallet-origin/index.d.ts',
  'wallet-origin/index.js',
]);

const ALLOWED_PUBLIC_PROTOCOL_LITERALS = Object.freeze([
  'password-scrypt-v2',
  'sdn-fast-password-auth-v1-legacy',
  'sdn-bip39-auth-v1-legacy',
]);

const UI_EXPORTS = Object.freeze({
  '.': { types: './dist/compat/index.d.ts', import: './dist/compat/index.js' },
  './client': { types: './dist/client/index.d.ts', import: './dist/client/index.js' },
  './client/asset-review': {
    types: './dist/client/asset-review.d.ts',
    import: './dist/client/asset-review.js',
  },
  './client/callback': {
    types: './dist/client/callback.d.ts',
    import: './dist/client/callback.js',
  },
  './client/sdn': { types: './dist/client/sdn.d.ts', import: './dist/client/sdn.js' },
  './styles': './dist/client/style.css',
  './wallet-origin': {
    types: './dist/wallet-origin/index.d.ts',
    import: './dist/wallet-origin/index.js',
  },
});

const CORE_EXPORTS = Object.freeze({
  '.': { types: './dist/runtime/index.d.ts', import: './dist/runtime/index.mjs' },
  './aligned': {
    types: './dist/runtime/aligned.d.ts',
    import: './dist/runtime/aligned.mjs',
  },
  './attestation': {
    types: './dist/runtime/epm-attestation.d.ts',
    import: './dist/runtime/epm-attestation.mjs',
  },
  './dist/hd-wallet-wasi.wasm': './dist/hd-wallet-wasi.wasm',
  './wasi.wasm': './dist/hd-wallet-wasi.wasm',
  './wasm': { types: './dist/wasm-loader.d.ts', import: './dist/hd-wallet.js' },
});

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function readBuilt(path) {
  const absolute = join(distDirectory, path);
  expect(await exists(absolute), `missing release output ${path}`).toBe(true);
  return readFile(absolute);
}

async function walk(directory, base = directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path, base));
    else output.push(relative(base, path).replaceAll('\\', '/'));
  }
  return output.sort();
}

function digest(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function redactExactPublicProtocolLiterals(source, label) {
  let scanned = source;
  for (const literal of ALLOWED_PUBLIC_PROTOCOL_LITERALS) {
    const quoted = new RegExp(`(["'])${escapeRegExp(literal)}\\1`, 'gu');
    scanned = scanned.replace(quoted, '"<allowed-public-protocol-literal>"');
    expect(scanned, `${label}: ${literal} must appear only as an exact quoted literal`)
      .not.toContain(literal);
  }
  return scanned;
}

describe('packed export contracts', () => {
  test('UI exposes exactly seven dist-only typed exports and a strict file allowlist', async () => {
    const manifest = JSON.parse(await readFile(join(walletUiDirectory, 'package.json'), 'utf8'));
    expect(manifest.main).toBe('./dist/compat/index.js');
    expect(manifest.module).toBe('./dist/compat/index.js');
    expect(manifest.types).toBe('./dist/compat/index.d.ts');
    expect(manifest.exports).toEqual(UI_EXPORTS);
    expect(manifest.dependencies).toEqual({ 'hd-wallet-wasm': '2.0.26' });
    expect(manifest.sideEffects).toEqual(['./dist/client/style.css']);
    expect(manifest.scripts.prepack).toBeUndefined();
    expect(manifest.files).toEqual([
      'dist/',
      'README.md',
      'LICENSE',
      'data/common-passwords-sdn-v1.txt',
      'data/common-passwords-sdn-v1.source.json',
    ]);
  });

  test('core runtime/type exports agree and publish only built output, README, and LICENSE', async () => {
    const manifest = JSON.parse(await readFile(join(repositoryDirectory, 'wasm/package.json'), 'utf8'));
    expect(manifest.main).toBe('./dist/runtime/index.mjs');
    expect(manifest.module).toBe('./dist/runtime/index.mjs');
    expect(manifest.types).toBe('./dist/runtime/index.d.ts');
    expect(manifest.exports).toEqual(CORE_EXPORTS);
    expect(manifest.files).toEqual([
      'dist/runtime/',
      'dist/hd-wallet.js',
      'dist/hd-wallet-wasi.wasm',
      'dist/wasm-loader.d.ts',
      'README.md',
      'LICENSE',
    ]);
  });

  test('both workspaces carry the repository license byte-for-byte', async () => {
    const rootLicense = await readFile(join(repositoryDirectory, 'LICENSE'));
    await expect(readFile(join(walletUiDirectory, 'LICENSE'))).resolves.toEqual(rootLicense);
    await expect(readFile(join(repositoryDirectory, 'wasm/LICENSE'))).resolves.toEqual(rootLicense);
  });
});

describe('release bundle isolation', () => {
  test('the generated docs target supports the verified registry module', () => {
    expect(walletViteConfig.build.target).toBe('es2022');
  });

  test('public outputs are fixed single-file graphs with no wallet-origin or secret runtime', async () => {
    const files = await walk(distDirectory);
    const expectedJavascript = [
      'browser/sdn-wallet-callback.js',
      'browser/sdn-wallet-public-client.js',
      'client/asset-review.js',
      'client/callback.js',
      'client/index.js',
      'client/sdn.js',
    ];
    const hostedAssets = files.filter((path) => path.startsWith('wallet-origin-host/assets/'));
    expect(hostedAssets).toEqual(expect.arrayContaining([
      expect.stringMatching(/^wallet-origin-host\/assets\/wallet-origin\.[0-9a-f]{64}\.js$/u),
      expect.stringMatching(/^wallet-origin-host\/assets\/wallet-origin\.[0-9a-f]{64}\.css$/u),
      expect.stringMatching(/^wallet-origin-host\/assets\/wallet-origin\.[0-9a-f]{64}\.wasm$/u),
    ]));
    expect(hostedAssets).toHaveLength(3);
    expect(files).toEqual([...STATIC_DIST_FILES, ...hostedAssets].sort());
    expect(files.some((path) => path.endsWith('.map'))).toBe(false);

    const publicFiles = [
      ...expectedJavascript.map((path) => join(distDirectory, path)),
      join(distDirectory, 'client/style.css'),
    ];
    const forbidden = [
      /\0asm/u,
      /\.wasm\b/iu,
      /\b(?:argon2|hkdf|pbkdf2|scrypt)\b/iu,
      /\b(?:deriveBits|deriveKey|importKey)\b/u,
      /\b(?:mnemonic|seed phrase|seedBytes|seedHandle)\b/iu,
      /\b(?:derivePasswordIdentity|getWalletOriginCapabilities|privateKey|secretHandle)\b/u,
      /\b(?:credentialPrompt|PasswordCredential|navigator\.credentials)\b/u,
      /(?:createElement\s*\(\s*["'](?:form|input)["']|type\s*=\s*["']password["']|autocomplete\s*=\s*["'](?:current|new)-password["'])/iu,
      /(?:@noble\b|@scure\b|\bbip39\b|\bcrypto-js\b)/iu,
      /\b(?:helius|provider[_-]?credential|api[_-]?key)\b/iu,
      /[A-Za-z0-9+/]{1024,}={0,2}/u,
      /\bimport\s*\(/u,
      /(?:@wallet|@sds|\.\.\/origin-app|\.\.\/src\/)/u,
    ];
    for (const path of publicFiles) {
      const label = relative(distDirectory, path);
      const source = redactExactPublicProtocolLiterals(await readFile(path, 'utf8'), label);
      expect(source, label).not.toMatch(/(?:boundaryVectors|asset-review-v1\.json|release\/protocol)/u);
      for (const pattern of forbidden) expect(source, `${label}: ${pattern}`)
        .not.toMatch(pattern);
    }
    for (const path of expectedJavascript.filter((path) => path.startsWith('client/'))) {
      const source = await readFile(join(distDirectory, path), 'utf8');
      expect(source, `${path} must have an inlined dependency graph`).not.toMatch(
        /(?:\bimport\s*(?:\(|["'{*])|\bfrom\s*["'])/u,
      );
    }
    expect(await readFile(join(distDirectory, 'client/style.css')))
      .toEqual(await readFile(join(walletUiDirectory, 'client/style.css')));

    const manifest = JSON.parse(await readFile(join(walletUiDirectory, 'package.json'), 'utf8'));
    for (const target of Object.values(manifest.exports)) {
      if (typeof target === 'string') {
        expect(await exists(join(walletUiDirectory, target))).toBe(true);
      } else {
        expect(await exists(join(walletUiDirectory, target.import))).toBe(true);
        expect(await exists(join(walletUiDirectory, target.types))).toBe(true);
      }
    }
  });

  test('every public source dependency stays inside the client-only graph', async () => {
    const canonicalReviewPolicy = JSON.parse(await readFile(
      join(repositoryDirectory, 'release/protocol/asset-review-v1.json'),
      'utf8',
    ));
    const clientReviewPolicy = (await import('../client/asset-review-policy.mjs')).default;
    expect(clientReviewPolicy).toEqual({
      reviewedTransform: canonicalReviewPolicy.reviewedTransform,
      schemaVersion: canonicalReviewPolicy.schemaVersion,
    });
    const assertRecursivelyFrozen = (value) => {
      if (value === null || typeof value !== 'object') return;
      expect(Object.isFrozen(value)).toBe(true);
      for (const nested of Object.values(value)) assertRecursivelyFrozen(nested);
    };
    assertRecursivelyFrozen(clientReviewPolicy);
    const queue = [
      'client/index.mjs',
      'client/sdn.mjs',
      'client/asset-review.mjs',
      'client/callback.mjs',
      'client/callback-entry.mjs',
      'client/public-entry.mjs',
    ].map((path) => join(walletUiDirectory, path));
    const visited = new Set();
    while (queue.length > 0) {
      const path = queue.shift();
      if (visited.has(path)) continue;
      visited.add(path);
      expect(relative(walletUiDirectory, path).replaceAll('\\', '/')).toMatch(/^client\//u);
      const source = await readFile(path, 'utf8');
      const imports = [
        ...source.matchAll(/\bfrom\s*["']([^"']+)["']/gu),
        ...source.matchAll(/(?:^|\n)\s*import\s*["']([^"']+)["']/gu),
      ].map((match) => match[1]);
      for (const specifier of imports) {
        expect(specifier, `${relative(walletUiDirectory, path)} has a package import`)
          .toMatch(/^\.\.?\//u);
        const dependency = resolve(dirname(path), specifier);
        expect(relative(walletUiDirectory, dependency).replaceAll('\\', '/'))
          .toMatch(/^client\//u);
        queue.push(dependency);
      }
      expect(source).not.toMatch(/\bimport\s*\(/u);
    }
    expect([...visited].length).toBeGreaterThan(5);
  });

  test('installed compatibility graphs have only approved imports', async () => {
    const compat = await readFile(join(distDirectory, 'compat/index.js'), 'utf8');
    const origin = await readFile(join(distDirectory, 'wallet-origin/index.js'), 'utf8');
    expect([...compat.matchAll(/\bfrom\s+["']([^"']+)["']/gu)].map((match) => match[1]))
      .toEqual(['hd-wallet-wasm', '../wallet-origin/index.js']);
    expect([...origin.matchAll(/\bfrom\s+["']([^"']+)["']/gu)].map((match) => match[1]))
      .toEqual(['hd-wallet-wasm']);
    for (const [label, source] of [['compat', compat], ['wallet-origin', origin]]) {
      expect(source, label).not.toMatch(/\bimport\s*\(/u);
      expect(source, label).not.toMatch(/(?:@wallet|@sds|\/src\/|node_modules|window\.Buffer)/u);
    }
  });

  test('shipped text contains no repository, worktree, or file URL', async () => {
    const files = await walk(distDirectory);
    const textFiles = files.filter((path) => /\.(?:css|d\.ts|html|js|json)$/u.test(path));
    for (const path of textFiles) {
      const source = await readFile(join(distDirectory, path), 'utf8');
      expect(source, path).not.toContain(repositoryDirectory);
      expect(source, path).not.toMatch(/(?:file:\/\/|\/Users\/|\.worktrees\/|sdn-wallet-rollout)/u);
    }
  });

  test('classic public and callback builds contain no module syntax or extra chunks', async () => {
    for (const path of [
      'browser/sdn-wallet-public-client.js',
      'browser/sdn-wallet-callback.js',
    ]) {
      const source = (await readBuilt(path)).toString('utf8');
      expect(source).not.toMatch(/\b(?:import|export)\b/u);
      expect(source).not.toMatch(/\bimport\s*\(/u);
    }

    const callbackBytes = await readBuilt('browser/sdn-wallet-callback.js');
    const callbackHtml = (await readBuilt('browser/wallet-callback.html')).toString('utf8');
    expect(callbackHtml).toBe(
      '<!doctype html>\n<meta charset="utf-8">\n'
      + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'">\n'
      + '<meta name="referrer" content="no-referrer">\n<title>Wallet return</title>\n'
      + `<script defer src="./sdn-wallet-callback.js" integrity="sha384-${digest('sha384', callbackBytes, 'base64')}" crossorigin="anonymous"></script>\n`,
    );
  });

  test('wallet-origin host has exactly one content-addressed JS, CSS, and split WASM', async () => {
    const manifest = JSON.parse(
      await readFile(join(walletUiDirectory, 'package.json'), 'utf8'),
    );
    const hostDirectory = join(distDirectory, 'wallet-origin-host');
    const files = await walk(hostDirectory);
    const assets = files.filter((path) => path.startsWith('assets/')).sort();
    expect(assets).toHaveLength(3);
    expect(assets).toEqual(expect.arrayContaining([
      expect.stringMatching(/^assets\/wallet-origin\.[0-9a-f]{64}\.js$/u),
      expect.stringMatching(/^assets\/wallet-origin\.[0-9a-f]{64}\.css$/u),
      expect.stringMatching(/^assets\/wallet-origin\.[0-9a-f]{64}\.wasm$/u),
    ]));
    expect(files.sort()).toEqual([...assets, 'index.html', 'integrity.json'].sort());

    const integrity = JSON.parse(await readFile(join(hostDirectory, 'integrity.json'), 'utf8'));
    expect(Object.keys(integrity.files).sort()).toEqual([...assets, 'index.html'].sort());
    for (const path of Object.keys(integrity.files)) {
      const bytes = await readFile(join(hostDirectory, path));
      expect(integrity.files[path]).toEqual({
        bytes: bytes.byteLength,
        sha256: digest('sha256', bytes),
        sha384: `sha384-${digest('sha384', bytes, 'base64')}`,
      });
      const match = /^assets\/wallet-origin\.([0-9a-f]{64})\.(?:css|js|wasm)$/u.exec(path);
      if (match) expect(match[1]).toBe(digest('sha256', bytes));
    }

    const html = await readFile(join(hostDirectory, 'index.html'), 'utf8');
    const css = await readFile(join(hostDirectory, assets.find((path) => path.endsWith('.css'))), 'utf8');
    const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'";
    expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="${csp}">`);
    expect(html).not.toMatch(/<(?:script|img|link)[^>]+(?:src|href)=["']https?:/iu);
    expect(html).not.toMatch(/<link[^>]+rel=["'](?:preload|prefetch)["']/iu);
    expect(`${html}\n${css}`).not.toMatch(/(?:url\s*\(|@import\s+)["']?https?:/iu);
    expect(css).toMatch(new RegExp(
      `--sdn-wallet-origin-style-ready:\\s*"${escapeRegExp(manifest.version)}"`,
      'u',
    ));
    expect(css).toMatch(/max-width:\s*320px/u);
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/u);
    for (const path of assets.filter((path) => !path.endsWith('.wasm'))) {
      expect(html).toContain(`/${path}`);
      expect(new URL(`/${path}`, 'https://wallet.spacedatanetwork.org/').href)
        .toBe(`https://wallet.spacedatanetwork.org/${path}`);
      expect(new URL(`/${path}`, 'https://wallet.spacedatanetwork.org/transaction/example').href)
        .toBe(`https://wallet.spacedatanetwork.org/${path}`);
    }
    const htmlJavascriptPath = assets.find((path) => path.endsWith('.js'));
    const htmlCssPath = assets.find((path) => path.endsWith('.css'));
    const htmlWasmPath = assets.find((path) => path.endsWith('.wasm'));
    expect(html).not.toContain(`/${htmlWasmPath}`);
    expect(html).not.toMatch(/\.wasm\b/iu);
    expect(html).toContain(
      `href="/${htmlCssPath}" integrity="${integrity.files[htmlCssPath].sha384}" crossorigin="anonymous"`,
    );
    expect(html).toContain(
      `src="/${htmlJavascriptPath}" integrity="${integrity.files[htmlJavascriptPath].sha384}" crossorigin="anonymous"`,
    );

    const javascriptPath = assets.find((path) => path.endsWith('.js'));
    const wasmPath = assets.find((path) => path.endsWith('.wasm'));
    const wasm = await readFile(join(hostDirectory, wasmPath));
    expect(wasm.byteLength).toBeGreaterThan(8);
    expect(wasm.byteLength).toBeLessThanOrEqual(4 * 1024 * 1024);
    expect(wasm.subarray(0, 8)).toEqual(Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
    const javascript = await readFile(join(hostDirectory, javascriptPath), 'utf8');
    expect(Buffer.byteLength(javascript)).toBeLessThan(1_000_000);
    expect(javascript).not.toMatch(/(?:data:[^,;]*;base64,|AGFzbQE|globalThis\.HDWalletWasm)/iu);
    expect(javascript).not.toMatch(/Module\[["']locateFile["']\]/u);
    expect(javascript).not.toMatch(/[A-Za-z0-9+/]{1024,}={0,2}/u);
    expect(javascript).not.toMatch(/serviceWorker\s*\.\s*register/u);
    expect(javascript).not.toMatch(/https?:[^"'`]*(?:\.js|\.css|\.wasm|\.woff2?|\.ttf|\.png|\.jpe?g|\.svg)/iu);
    const wasmName = wasmPath.split('/').at(-1);
    const javascriptName = javascriptPath.split('/').at(-1);
    expect(javascript.match(new RegExp(`\\./${escapeRegExp(wasmName)}`, 'gu'))).toHaveLength(1);
    expect(new URL(`./${wasmName}`, `https://wallet.spacedatanetwork.org/assets/${javascriptName}`).href)
      .toBe(`https://wallet.spacedatanetwork.org/assets/${wasmName}`);
    expect(javascript).toContain(integrity.files[wasmPath].sha384);
    for (const contract of [
      /cache:\s*["']no-store["']/u,
      /credentials:\s*["']omit["']/u,
      /mode:\s*["']same-origin["']/u,
      /redirect:\s*["']error["']/u,
      /referrerPolicy:\s*["']no-referrer["']/u,
      /content-length/iu,
      /(?:4194304|4\s*\*\s*1024\s*\*\s*1024)/u,
      /getReader/u,
      /wasmBinary/u,
    ]) expect(javascript).toMatch(contract);
  });

  test('two clean release builds are byte-for-byte deterministic', async () => {
    const command = [join(walletUiDirectory, 'scripts/build-release.mjs')];
    const options = {
      cwd: walletUiDirectory,
      env: { ...process.env, npm_config_offline: 'true' },
      stdio: 'pipe',
    };
    execFileSync(process.execPath, command, options);
    const firstFiles = await walk(distDirectory);
    const first = new Map();
    for (const path of firstFiles) first.set(path, await readFile(join(distDirectory, path)));

    execFileSync(process.execPath, command, options);
    expect(await walk(distDirectory)).toEqual(firstFiles);
    for (const [path, bytes] of first) {
      expect(await readFile(join(distDirectory, path)), path).toEqual(bytes);
    }
  }, 60_000);
});
