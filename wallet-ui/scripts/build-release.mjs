import { createHash } from 'node:crypto';
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build as viteBuild } from 'vite';

import { createReleaseLibraryConfig } from '../vite.config.js';
import {
  createWalletOriginBuildConfig,
  WASM_INTEGRITY_PLACEHOLDER,
} from '../vite.wallet-origin.config.js';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const walletUiDirectory = resolve(scriptDirectory, '..');
const repositoryDirectory = resolve(walletUiDirectory, '..');
const outputDirectory = resolve(walletUiDirectory, 'dist');
const wasmDirectory = resolve(repositoryDirectory, 'wasm');

const CLIENT_ENTRIES = Object.freeze([
  ['client/index.mjs', 'client/index.js'],
  ['client/sdn.mjs', 'client/sdn.js'],
  ['client/asset-review.mjs', 'client/asset-review.js'],
  ['client/callback.mjs', 'client/callback.js'],
]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

function integrityRecord(bytes) {
  return { bytes: bytes.byteLength, sha256: sha256(bytes), sha384: sha384(bytes) };
}

async function buildLibrary(entry, fileName, format = 'es', name = undefined, external = []) {
  await mkdir(dirname(resolve(outputDirectory, fileName)), { recursive: true });
  const config = createReleaseLibraryConfig({
    entry: resolve(walletUiDirectory, entry),
    fileName,
    format,
    name,
    outDir: outputDirectory,
  });
  config.build.rollupOptions.external = external;
  await viteBuild(config);
}

async function copyDeclarations() {
  const clientDirectory = resolve(outputDirectory, 'client');
  await mkdir(clientDirectory, { recursive: true });
  for (const file of ['index.d.ts', 'sdn.d.ts', 'asset-review.d.ts', 'callback.d.ts', 'types.d.ts']) {
    await copyFile(resolve(walletUiDirectory, 'client', file), resolve(clientDirectory, file));
  }
  await copyFile(
    resolve(walletUiDirectory, 'client/style.css'),
    resolve(clientDirectory, 'style.css'),
  );
}

function compatibilityEntry() {
  return `import initHDWallet from 'hd-wallet-wasm';
import { createWalletOriginApp } from '../wallet-origin/index.js';

export function normalizeTabHash(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/^#/, '').trim().toLowerCase();
  return /^[a-z][a-z0-9-]{0,63}$/u.test(normalized) ? normalized : null;
}

export function normalizeCreateWalletUIArguments(rootElementOrOptions, options = {}) {
  const NodeConstructor = globalThis.Node;
  const isNode = typeof NodeConstructor === 'function'
    && rootElementOrOptions instanceof NodeConstructor;
  if (isNode || rootElementOrOptions === null || rootElementOrOptions === undefined) {
    return { element: rootElementOrOptions ?? null, options: options ?? {} };
  }
  if (typeof rootElementOrOptions !== 'object' || Array.isArray(rootElementOrOptions)) {
    throw new TypeError('createWalletUI expects an element or an options object');
  }
  const { element = null, ...objectOptions } = rootElementOrOptions;
  if (element !== null
      && !(typeof NodeConstructor === 'function' && element instanceof NodeConstructor)) {
    throw new TypeError('createWalletUI element must be a DOM Node');
  }
  return { element, options: objectOptions };
}

export async function createWalletUI(rootElementOrOptions, options = {}) {
  const normalized = normalizeCreateWalletUIArguments(rootElementOrOptions, options);
  const configuration = normalized.options ?? {};
  const documentObject = configuration.document
    ?? normalized.element?.ownerDocument
    ?? globalThis.document;
  const windowObject = configuration.window
    ?? documentObject?.defaultView
    ?? globalThis.window;
  const wasm = await (configuration.wasm ?? initHDWallet());
  const app = createWalletOriginApp({
    clipboard: configuration.clipboard,
    credentialPrompt: configuration.credentialPrompt,
    document: documentObject,
    fetch: configuration.fetch,
    location: configuration.location,
    mount: normalized.element ?? documentObject?.body,
    registry: configuration.registry,
    relay: configuration.relay,
    rng: configuration.rng,
    wasm,
    window: windowObject,
  });
  const open = () => app.start();
  return Object.freeze({
    openLogin: open,
    openAccount: open,
    logout: () => app.logout(),
    destroy: () => app.stop('destroy'),
  });
}

export async function init(rootElementOrOptions, options = {}) {
  return createWalletUI(rootElementOrOptions, options);
}
`;
}

function compatibilityDeclaration() {
  return `export interface WalletUiController {
  readonly openLogin: () => Promise<unknown>;
  readonly openAccount: () => Promise<unknown>;
  readonly logout: () => Promise<unknown>;
  readonly destroy: () => Promise<unknown>;
}
export interface CreateWalletUiOptions {
  readonly element?: Node | null;
  readonly document?: Document;
  readonly window?: Window;
  readonly wasm?: object;
  readonly [name: string]: unknown;
}
export declare function normalizeTabHash(value: unknown): string | null;
export declare function normalizeCreateWalletUIArguments(
  rootElementOrOptions?: Node | CreateWalletUiOptions | null,
  options?: CreateWalletUiOptions,
): { element: Node | null; options: CreateWalletUiOptions };
export declare function createWalletUI(
  rootElementOrOptions?: Node | CreateWalletUiOptions | null,
  options?: CreateWalletUiOptions,
): Promise<WalletUiController>;
export declare function init(
  rootElementOrOptions?: Node | CreateWalletUiOptions | null,
  options?: CreateWalletUiOptions,
): Promise<WalletUiController>;
`;
}

function walletOriginDeclaration() {
  return `export interface WalletOriginApplication {
  readonly controller: object;
  start(): Promise<unknown>;
  stop(reason?: string): Promise<void>;
  logout(): Promise<unknown>;
}
export interface WalletOriginConfiguration {
  readonly wasm: object;
  readonly document?: Document;
  readonly window?: Window;
  readonly mount?: Element;
  readonly [name: string]: unknown;
}
export declare function createWalletOriginApp(
  configuration: WalletOriginConfiguration,
): WalletOriginApplication;
export declare function mountWalletOriginApp(
  configuration: WalletOriginConfiguration,
): Promise<WalletOriginApplication>;
export declare function transactionIdFromLocation(location: Location): string;
export declare function createPasswordCredentialPrompt(configuration: object): object;
`;
}

async function buildCompatibilityEntry() {
  const directory = resolve(outputDirectory, 'compat');
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'index.js'), compatibilityEntry());
  await writeFile(resolve(directory, 'index.d.ts'), compatibilityDeclaration());
}

async function buildInstalledWalletOrigin() {
  await buildLibrary(
    'origin-app/app.mjs',
    'wallet-origin/index.js',
    'es',
    undefined,
    ['hd-wallet-wasm'],
  );
  await writeFile(
    resolve(outputDirectory, 'wallet-origin/index.d.ts'),
    walletOriginDeclaration(),
  );
}

async function buildClassicOutputs() {
  await buildLibrary(
    'client/public-entry.mjs',
    'browser/sdn-wallet-public-client.js',
    'iife',
    'SDNWalletPublicClientBundle',
  );
  await buildLibrary(
    'client/callback-entry.mjs',
    'browser/sdn-wallet-callback.js',
    'iife',
    'SDNWalletCallbackBundle',
  );
  const callback = await readFile(
    resolve(outputDirectory, 'browser/sdn-wallet-callback.js'),
  );
  const html = '<!doctype html>\n<meta charset="utf-8">\n'
    + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'">\n'
    + '<meta name="referrer" content="no-referrer">\n<title>Wallet return</title>\n'
    + `<script defer src="./sdn-wallet-callback.js" integrity="${sha384(callback)}" crossorigin="anonymous"></script>\n`;
  await writeFile(resolve(outputDirectory, 'browser/wallet-callback.html'), html);
}

async function buildWalletOriginHost() {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), 'sdn-wallet-origin-build-'));
  try {
    await viteBuild(createWalletOriginBuildConfig({ outDir: temporaryDirectory }));
    const names = (await readdir(temporaryDirectory)).sort();
    if (JSON.stringify(names) !== JSON.stringify([
      'wallet-origin.css',
      'wallet-origin.js',
      'wallet-origin.wasm',
    ])) {
      throw new Error(`Unexpected wallet-origin output: ${names.join(', ')}`);
    }

    const wasm = await readFile(resolve(temporaryDirectory, 'wallet-origin.wasm'));
    const wasmHeader = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    if (wasm.byteLength < wasmHeader.byteLength || wasm.byteLength > 4 * 1024 * 1024
        || !wasm.subarray(0, wasmHeader.byteLength).equals(wasmHeader)) {
      throw new Error('wallet-origin WASM artifact is invalid');
    }
    const css = await readFile(resolve(temporaryDirectory, 'wallet-origin.css'));
    const rawJavascript = await readFile(resolve(temporaryDirectory, 'wallet-origin.js'), 'utf8');
    const wasmName = `wallet-origin.${sha256(wasm)}.wasm`;
    const wasmUrlMatches = rawJavascript.match(/wallet-origin\.wasm/gu) ?? [];
    if (wasmUrlMatches.length !== 1) {
      throw new Error(`Expected one wallet-origin WASM URL, found ${wasmUrlMatches.length}`);
    }
    let javascript = rawJavascript.replace('wallet-origin.wasm', `./${wasmName}`);
    if (javascript.includes('wallet-origin.wasm')) {
      throw new Error('unhashed wallet-origin WASM URL remains');
    }
    const wasmIntegrity = sha384(wasm);
    javascript = javascript.replaceAll(WASM_INTEGRITY_PLACEHOLDER, wasmIntegrity);
    if (javascript.includes(WASM_INTEGRITY_PLACEHOLDER)) {
      throw new Error('wallet-origin WASM integrity placeholder remains');
    }
    if (!javascript.includes(wasmIntegrity)) {
      throw new Error('wallet-origin WASM integrity was not bound');
    }
    const javascriptBytes = Buffer.from(javascript);
    const javascriptName = `wallet-origin.${sha256(javascriptBytes)}.js`;
    const cssName = `wallet-origin.${sha256(css)}.css`;
    const hostDirectory = resolve(outputDirectory, 'wallet-origin-host');
    const assetDirectory = resolve(hostDirectory, 'assets');
    await mkdir(assetDirectory, { recursive: true });
    await writeFile(resolve(assetDirectory, wasmName), wasm);
    await writeFile(resolve(assetDirectory, cssName), css);
    await writeFile(resolve(assetDirectory, javascriptName), javascriptBytes);

    const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'";
    const html = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
      + `<meta http-equiv="Content-Security-Policy" content="${csp}">\n`
      + '<meta name="referrer" content="no-referrer">\n'
      + '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
      + '<title>SDN Wallet</title>\n'
      + `<link rel="stylesheet" href="/assets/${cssName}" integrity="${sha384(css)}" crossorigin="anonymous">\n`
      + '</head><body><main data-wallet-origin-root aria-live="polite"></main>\n'
      + `<script type="module" src="/assets/${javascriptName}" integrity="${sha384(javascriptBytes)}" crossorigin="anonymous"></script>\n`
      + '</body></html>\n';
    const htmlBytes = Buffer.from(html);
    await writeFile(resolve(hostDirectory, 'index.html'), htmlBytes);

    const files = Object.fromEntries([
      [`assets/${cssName}`, integrityRecord(css)],
      [`assets/${javascriptName}`, integrityRecord(javascriptBytes)],
      [`assets/${wasmName}`, integrityRecord(wasm)],
      ['index.html', integrityRecord(htmlBytes)],
    ]);
    await writeFile(resolve(hostDirectory, 'integrity.json'), `${JSON.stringify({
      files,
      schemaVersion: 1,
    })}\n`);
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

async function validateLicenses() {
  const root = await readFile(resolve(repositoryDirectory, 'LICENSE'));
  for (const path of [
    resolve(walletUiDirectory, 'LICENSE'),
    resolve(wasmDirectory, 'LICENSE'),
  ]) {
    const local = await readFile(path);
    if (!local.equals(root)) throw new Error(`Package license differs from root: ${path}`);
  }
}

export async function buildRelease() {
  if (process.argv.length > 2) throw new Error('build-release accepts no path arguments');
  await rm(outputDirectory, { force: true, recursive: true });
  await mkdir(outputDirectory, { recursive: true });
  await validateLicenses();
  for (const [entry, fileName] of CLIENT_ENTRIES) await buildLibrary(entry, fileName);
  await copyDeclarations();
  await buildInstalledWalletOrigin();
  await buildCompatibilityEntry();
  await buildClassicOutputs();
  await buildWalletOriginHost();
}

await buildRelease();
