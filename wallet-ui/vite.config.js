import { defineConfig } from 'vite';
import { createRequire } from 'module';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const configDir = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(configDir, '..', 'wasm', 'package.json'), 'utf-8'));
const require = createRequire(import.meta.url);
const sdsPackageRoot = dirname(require.resolve('spacedatastandards.org/package.json'));

export function createReleaseLibraryConfig({
  entry,
  fileName,
  format,
  name,
  outDir,
}) {
  return defineConfig({
    base: './',
    build: {
      assetsInlineLimit: 0,
      cssCodeSplit: false,
      emptyOutDir: false,
      lib: {
        entry,
        fileName: () => fileName,
        formats: [format],
        ...(name ? { name } : {}),
      },
      minify: 'esbuild',
      outDir,
      rollupOptions: {
        output: {
          inlineDynamicImports: true,
        },
      },
      sourcemap: false,
      target: 'es2022',
    },
    configFile: false,
    publicDir: false,
  });
}

export default defineConfig({
  root: '.',
  base: './',
  test: {
    // Relay fixtures use Node's built-in test runner and have their own
    // package command. Keep the UI Vitest suite scoped to UI-owned tests.
    include: ['test/**/*.test.{js,mjs}'],
  },
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: {
      '@wallet': resolve(configDir, 'src'),
      '@sds': sdsPackageRoot,
    },
  },
  optimizeDeps: {
    include: ['qrcode', 'buffer', 'vcard-cryptoperson'],
    exclude: ['hd-wallet-wasm'],
  },
  build: {
    outDir: 'dist',
    // Registry verification intentionally uses top-level await before any
    // wallet-origin credentials can render. Keep the generated demo/docs
    // target aligned with that security boundary.
    target: 'es2022',
    rollupOptions: {
      input: {
        main: resolve(configDir, 'index.html'),
      },
      external: ['fs', 'url', 'path', 'module', 'crypto'],
      onwarn(warning, warn) {
        if (warning.code === 'MODULE_LEVEL_DIRECTIVE' ||
            (warning.message && warning.message.includes('has been externalized for browser compatibility'))) {
          return;
        }
        warn(warning);
      },
    },
  },
  server: {
    port: 3494,
    open: true,
    fs: {
      allow: [
        resolve(configDir, '..'),
        sdsPackageRoot,
      ],
    },
    proxy: {
      '/api/blockchain': {
        target: 'https://blockchain.info',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/blockchain/, ''),
      },
      '/api/blockstream': {
        target: 'https://blockstream.info',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/blockstream/, ''),
      },
      '/api/eth': {
        target: 'https://cloudflare-eth.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/eth/, ''),
      },
      '/api/solana/official': {
        target: 'https://api.mainnet-beta.solana.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/official/, ''),
      },
      '/api/solana/publicnode': {
        target: 'https://solana-rpc.publicnode.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/publicnode/, ''),
      },
      '/api/solana/helius': {
        target: 'https://mainnet.helius-rpc.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/helius/, ''),
      },
      /* Commented out — BTC/ETH/SOL only for now
      '/api/sui': { target: 'https://fullnode.mainnet.sui.io:443', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/sui/, '') },
      '/api/monad': { target: 'https://testnet-rpc.monad.xyz', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/monad/, '') },
      '/api/koios': { target: 'https://api.koios.rest', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/koios/, '') },
      '/api/xrp': { target: 'https://s1.ripple.com:51234', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/xrp/, '') },
      */
      '/api/coinbase': {
        target: 'https://api.coinbase.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/coinbase/, ''),
      },
      '/api/hiro': {
        target: 'https://api.hiro.so',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/hiro/, ''),
      },
    },
  },
  publicDir: 'public',
});
