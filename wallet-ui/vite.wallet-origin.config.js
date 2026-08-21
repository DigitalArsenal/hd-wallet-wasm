import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, normalizePath } from 'vite';

const configDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(configDirectory, '..');
const wasmIndex = normalizePath(resolve(repositoryDirectory, 'wasm/src/index.mjs'));
const splitWasmLoader = normalizePath(resolve(
  repositoryDirectory,
  'build-wasm/wasm/browser/hd-wallet.js',
));
const splitWasmBinary = normalizePath(resolve(
  repositoryDirectory,
  'build-wasm/wasm/browser/hd-wallet.wasm',
));
const originEntry = normalizePath(resolve(configDirectory, 'origin-app/host-entry.mjs'));
const WASM_ASSET_ID = '\0sdn-wallet-origin-wasm-asset';
export const WASM_INTEGRITY_PLACEHOLDER = 'sha384-SDN_WALLET_ORIGIN_WASM_INTEGRITY_PLACEHOLDER';

export function transformSplitWasmLoader(code) {
  const replacements = [
    [
      'function(moduleArg = {}) {\n\nvar Module=moduleArg;',
      'function(moduleArg = {}) {if(!(moduleArg.wasmBinary instanceof Uint8Array))'
      + 'throw new Error("Verified WASM bytes are required");\n\nvar Module=moduleArg;',
    ],
    [
      'function locateFile(path){if(Module["locateFile"]){return Module["locateFile"](path,scriptDirectory)}return scriptDirectory+path}',
      'function locateFile(path){return scriptDirectory+path}',
    ],
    [
      'var dataURIPrefix="data:application/octet-stream;base64,";var isDataURI=filename=>filename.startsWith(dataURIPrefix);',
      'var isDataURI=()=>false;',
    ],
    [
      'var wasmBinaryFile;if(Module["locateFile"]){wasmBinaryFile="hd-wallet.wasm";if(!isDataURI(wasmBinaryFile)){wasmBinaryFile=locateFile(wasmBinaryFile)}}else{wasmBinaryFile=new URL("hd-wallet.wasm",import.meta.url).href}',
      'var wasmBinaryFile="verified-binary";',
    ],
  ];
  let transformed = code;
  for (const [before, after] of replacements) {
    if (transformed.split(before).length !== 2) {
      throw new Error('wallet-origin split loader seam no longer matches exactly once');
    }
    transformed = transformed.replace(before, after);
  }
  if (transformed.includes('Module["locateFile"]')
      || transformed.includes('new URL("hd-wallet.wasm",import.meta.url).href')
      || transformed.includes('data:application/octet-stream;base64,')) {
    throw new Error('wallet-origin split loader retains an unsafe WASM resolution path');
  }
  return transformed;
}

function walletOriginPlugin() {
  return {
    enforce: 'pre',
    name: 'sdn-wallet-origin-isolation',
    resolveId(source, importer) {
      if (normalizePath(source) === `${splitWasmBinary}?url`) return WASM_ASSET_ID;
      if (source === 'hd-wallet-wasm') return wasmIndex;
      if (source === '../dist/hd-wallet.js' && normalizePath(importer ?? '') === wasmIndex) {
        return splitWasmLoader;
      }
      return null;
    },
    load(id) {
      if (id !== WASM_ASSET_ID) return null;
      const referenceId = this.emitFile({
        name: 'wallet-origin.wasm',
        source: readFileSync(splitWasmBinary),
        type: 'asset',
      });
      return `export default import.meta.ROLLUP_FILE_URL_${referenceId};`;
    },
    transform(code, id) {
      if (normalizePath(id) === splitWasmLoader) {
        return { code: transformSplitWasmLoader(code), map: null };
      }
      if (normalizePath(id) !== wasmIndex) return null;
      const start = code.indexOf('async function loadWasmModule() {');
      const endMarker = '\n}\n\n/**\n * Create the HD Wallet module instance';
      const end = code.indexOf(endMarker, start);
      if (start < 0 || end < 0) throw new Error('wallet-origin loader seam no longer matches');
      const loader = `async function loadWasmModule() {
  const module = await import('../dist/hd-wallet.js');
  const factory = module?.default;
  if (typeof factory !== 'function') throw new Error('Wallet WASM loader is invalid');
  const expectedUrl = new URL(walletOriginWasmUrl, import.meta.url).href;
  const response = await fetch(expectedUrl, {
    cache: 'no-store',
    credentials: 'omit',
    integrity: ${JSON.stringify(WASM_INTEGRITY_PLACEHOLDER)},
    mode: 'same-origin',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 200 || response.redirected || response.url !== expectedUrl
      || response.headers.get('content-type') !== 'application/wasm'
      || typeof response.body?.getReader !== 'function') {
    throw new Error('Wallet WASM response is invalid');
  }
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null
      && (!/^(?:0|[1-9]\\d*)$/u.test(declaredLength)
        || Number(declaredLength) > 4 * 1024 * 1024)) {
    throw new Error('Wallet WASM response is too large');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('Wallet WASM response is invalid');
      total += value.byteLength;
      if (total > 4 * 1024 * 1024) throw new Error('Wallet WASM response is too large');
      chunks.push(value);
    }
  } catch (error) {
    try { await reader.cancel(); } catch { /* bounded failure */ }
    throw error;
  } finally {
    try { reader.releaseLock(); } catch { /* terminal cleanup */ }
  }
  const wasmBinary = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    wasmBinary.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return factory({ wasmBinary });
}`;
      return {
        code: `import walletOriginWasmUrl from ${JSON.stringify(`${splitWasmBinary}?url`)};\n${code.slice(0, start)}${loader}${code.slice(end + 2)}`,
        map: null,
      };
    },
  };
}

export function createWalletOriginBuildConfig({ outDir }) {
  return defineConfig({
    base: './',
    build: {
      assetsInlineLimit: 0,
      cssCodeSplit: false,
      emptyOutDir: false,
      lib: {
        entry: originEntry,
        fileName: () => 'wallet-origin.js',
        formats: ['es'],
      },
      minify: 'esbuild',
      outDir,
      rollupOptions: {
        output: {
          assetFileNames(assetInfo) {
            const name = assetInfo.names?.[0] ?? assetInfo.name ?? '';
            if (name.endsWith('.css')) return 'wallet-origin.css';
            if (name.endsWith('.wasm')) return 'wallet-origin.wasm';
            throw new Error(`Unexpected wallet-origin asset: ${name}`);
          },
          entryFileNames: 'wallet-origin.js',
          inlineDynamicImports: true,
        },
      },
      sourcemap: false,
      target: 'es2022',
    },
    configFile: false,
    plugins: [walletOriginPlugin()],
    publicDir: false,
  });
}

export default createWalletOriginBuildConfig({
  outDir: resolve(configDirectory, 'dist/wallet-origin-host'),
});
