import { describe, expect, it } from 'vitest';

import * as walletOriginConfig from '../vite.wallet-origin.config.js';

const EMSCRIPTEN_3_1_51_LOADER = `var HDWalletWasm = (() => {
  var _scriptDir = import.meta.url;
  return (
function(moduleArg = {}) {

var Module=moduleArg;var scriptDirectory="";function locateFile(path){if(Module["locateFile"]){return Module["locateFile"](path,scriptDirectory)}return scriptDirectory+path}var wasmBinary=Module["wasmBinary"];
var dataURIPrefix="data:application/octet-stream;base64,";var isDataURI=filename=>filename.startsWith(dataURIPrefix);var wasmBinaryFile;if(Module["locateFile"]){wasmBinaryFile="hd-wallet.wasm";if(!isDataURI(wasmBinaryFile)){wasmBinaryFile=locateFile(wasmBinaryFile)}}else{wasmBinaryFile=new URL("hd-wallet.wasm",import.meta.url).href}function getBinaryPromise(binaryFile){if(!wasmBinary){return fetch(binaryFile)}}
return moduleArg.ready
}
);
})();`;

describe('wallet-origin Emscripten loader isolation', () => {
  it('rewrites the frozen Emscripten 3.1.51 loader to require verified bytes', () => {
    expect(walletOriginConfig.transformSplitWasmLoader).toBeTypeOf('function');

    const transformed = walletOriginConfig.transformSplitWasmLoader(
      EMSCRIPTEN_3_1_51_LOADER,
    );

    expect(transformed).toContain(
      'function(moduleArg = {}) {if(!(moduleArg.wasmBinary instanceof Uint8Array))'
      + 'throw new Error("Verified WASM bytes are required");',
    );
    expect(transformed).toContain(
      'function locateFile(path){return scriptDirectory+path}',
    );
    expect(transformed).toContain(
      'var wasmBinaryFile="verified-binary";function getBinaryPromise',
    );
    expect(transformed).not.toContain('Module["locateFile"]');
    expect(transformed).not.toContain('new URL("hd-wallet.wasm",import.meta.url)');
    expect(transformed).not.toContain('data:application/octet-stream;base64,');
  });

  it.each([
    ['a missing seam', EMSCRIPTEN_3_1_51_LOADER.replace(
      'function(moduleArg = {}) {',
      'function(moduleArg={}){',
    )],
    ['a duplicate seam', `${EMSCRIPTEN_3_1_51_LOADER}\n${EMSCRIPTEN_3_1_51_LOADER}`],
  ])('fails closed when the loader has %s', (_description, loader) => {
    expect(() => walletOriginConfig.transformSplitWasmLoader(loader)).toThrow(
      'wallet-origin split loader seam no longer matches exactly once',
    );
  });

  it.each([
    ['caller locateFile access', 'Module["locateFile"]("hd-wallet.wasm")'],
    ['an implicit WASM URL', 'new URL("hd-wallet.wasm",import.meta.url).href'],
  ])('fails closed when transformed code retains %s', (_description, unsafeCode) => {
    expect(() => walletOriginConfig.transformSplitWasmLoader(
      `${EMSCRIPTEN_3_1_51_LOADER}\n${unsafeCode}`,
    )).toThrow('wallet-origin split loader retains an unsafe WASM resolution path');
  });
});
