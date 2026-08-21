export type EmscriptenValueType =
  | 'array'
  | 'boolean'
  | 'number'
  | 'string'
  | null;

export type EmscriptenArgumentType = Exclude<EmscriptenValueType, null>;

export interface HDWalletWasmModuleOptions {
  arguments?: string[];
  thisProgram?: string;
  noExitRuntime?: boolean;
  noFSInit?: boolean;
  preInit?: (() => void) | Array<() => void>;
  preRun?: (() => void) | Array<() => void>;
  postRun?: (() => void) | Array<() => void>;
  print?: (message: string) => void;
  printErr?: (message: string) => void;
  setStatus?: (status: string) => void;
  monitorRunDependencies?: (remaining: number) => void;
  onAbort?: (reason: unknown) => void;
  onRuntimeInitialized?: () => void;
  locateFile?: (path: string, scriptDirectory: string) => string;
  wasmBinary?: ArrayBuffer | Uint8Array;
  instantiateWasm?: (
    imports: WebAssembly.Imports,
    receiveInstance: (
      instance: WebAssembly.Instance,
      module?: WebAssembly.Module,
    ) => void,
  ) => WebAssembly.Exports | Promise<WebAssembly.Exports>;
}

export interface HDWalletWasmModule {
  readonly HEAPU8: Uint8Array;
  readonly HEAP32: Int32Array;
  readonly calledRun: boolean;
  _malloc(size: number): number;
  _free(pointer: number): void;
  ccall<Return = unknown>(
    identifier: string,
    returnType: EmscriptenValueType,
    argumentTypes: EmscriptenArgumentType[] | undefined,
    arguments_: unknown[] | undefined,
    options: { async: true },
  ): Promise<Return>;
  ccall<Return = unknown>(
    identifier: string,
    returnType: EmscriptenValueType,
    argumentTypes?: EmscriptenArgumentType[],
    arguments_?: unknown[],
    options?: { async?: false },
  ): Return;
  cwrap<Arguments extends unknown[] = unknown[], Return = unknown>(
    identifier: string,
    returnType: EmscriptenValueType,
    argumentTypes: EmscriptenArgumentType[] | undefined,
    options: { async: true },
  ): (...arguments_: Arguments) => Promise<Return>;
  cwrap<Arguments extends unknown[] = unknown[], Return = unknown>(
    identifier: string,
    returnType: EmscriptenValueType,
    argumentTypes?: EmscriptenArgumentType[],
    options?: { async?: false },
  ): (...arguments_: Arguments) => Return;
  getValue(pointer: number, type: string): number | bigint;
  setValue(pointer: number, value: number | bigint, type: string): void;
  UTF8ToString(pointer: number, maximumBytesToRead?: number): string;
  stringToUTF8(value: string, outputPointer: number, maximumBytesToWrite: number): number;
  lengthBytesUTF8(value: string): number;
}

export default function initializeHDWalletWasm(
  options?: HDWalletWasmModuleOptions,
): Promise<HDWalletWasmModule>;
