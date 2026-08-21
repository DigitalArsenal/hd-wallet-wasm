import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const wasmDirectory = join(repositoryDirectory, 'wasm');
const sourceDirectory = join(wasmDirectory, 'src');
const distDirectory = join(wasmDirectory, 'dist');
const runtimeDirectory = join(distDirectory, 'runtime');
const rawDeclaration = join(distDirectory, 'wasm-loader.d.ts');

const RUNTIME_FILES = Object.freeze([
  'aligned.d.ts',
  'aligned.mjs',
  'epm-attestation.d.ts',
  'epm-attestation.mjs',
  'generated/aligned/hd_wallet_aligned.mjs',
  'generated/sdn_plugin_manifest.mjs',
  'index.d.ts',
  'index.mjs',
  'sdn-plugin-manifest-codec.mjs',
  'sdn-plugin-manifest-source.mjs',
  'sdn-plugin.mjs',
  'sdn-typed.mjs',
]);

const WASM_HEADER = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);

function replaceExactlyOnce(source, before, after, label) {
  if (source.split(before).length !== 2) {
    throw new Error(`${label} seam must occur exactly once`);
  }
  return source.replace(before, after);
}

async function walk(directory, base = directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path, base));
    else if (entry.isFile()) output.push(relative(base, path).replaceAll('\\', '/'));
    else throw new Error(`unsupported staged entry: ${entry.name}`);
  }
  return output.sort();
}

async function validateBuildArtifacts() {
  const loader = await readFile(join(distDirectory, 'hd-wallet.js'), 'utf8');
  if (Buffer.byteLength(loader) < 1_024 || !loader.includes('HDWalletWasm')
      || !loader.includes('wasmBinary')) {
    throw new Error('core JavaScript loader is missing or invalid');
  }
  const wasi = await readFile(join(distDirectory, 'hd-wallet-wasi.wasm'));
  if (wasi.byteLength <= WASM_HEADER.byteLength
      || !wasi.subarray(0, WASM_HEADER.byteLength).equals(WASM_HEADER)) {
    throw new Error('core WASI artifact is missing or invalid');
  }
}

async function stageCorePackage() {
  if (process.argv.length !== 2) throw new Error('stage-core-package accepts no arguments');
  await validateBuildArtifacts();
  await mkdir(distDirectory, { recursive: true });
  const temporaryRuntime = await mkdtemp(join(distDirectory, '.runtime-stage-'));
  const temporaryDeclaration = join(distDirectory, '.wasm-loader.d.ts.stage');
  try {
    for (const file of RUNTIME_FILES) {
      const source = join(sourceDirectory, file);
      const target = join(temporaryRuntime, file);
      await mkdir(dirname(target), { recursive: true });
      if (file === 'index.mjs') {
        const value = await readFile(source, 'utf8');
        await writeFile(target, replaceExactlyOnce(
          value,
          "import('../dist/hd-wallet.js')",
          "import('../hd-wallet.js')",
          'core runtime loader',
        ));
      } else if (file === 'index.d.ts') {
        const value = await readFile(source, 'utf8');
        await writeFile(target, replaceExactlyOnce(
          value,
          "from './aligned';",
          "from './aligned.js';",
          'core NodeNext declaration',
        ));
      } else {
        await copyFile(source, target);
      }
    }
    const stagedFiles = await walk(temporaryRuntime);
    if (JSON.stringify(stagedFiles) !== JSON.stringify([...RUNTIME_FILES].sort())) {
      throw new Error(`unexpected core runtime inventory: ${stagedFiles.join(', ')}`);
    }
    await copyFile(join(sourceDirectory, 'wasm-loader.d.ts'), temporaryDeclaration);

    await rm(runtimeDirectory, { force: true, recursive: true });
    await rename(temporaryRuntime, runtimeDirectory);
    await rename(temporaryDeclaration, rawDeclaration);
  } finally {
    await rm(temporaryRuntime, { force: true, recursive: true });
    await rm(temporaryDeclaration, { force: true });
  }
}

await stageCorePackage();
