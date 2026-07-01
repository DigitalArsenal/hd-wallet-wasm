/**
 * HD Wallet WASM - Test Suite
 * Runs all test modules
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Check if WASM module exists
const jsPath = join(__dirname, '../dist/hd-wallet.js');

if (!existsSync(jsPath)) {
  console.log('WASM module not built yet. Skipping tests.');
  console.log('Run "npm run build" to build the WASM module first.');
  process.exit(0);
}

// Track results
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const failures = [];

/**
 * Simple test framework
 */
export function test(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } catch (error) {
    failedTests++;
    failures.push({ name, error });
    console.log(`  \x1b[31m✗\x1b[0m ${name}`);
    console.log(`    ${error.message}`);
  }
}

export async function testAsync(name, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } catch (error) {
    failedTests++;
    failures.push({ name, error });
    console.log(`  \x1b[31m✗\x1b[0m ${name}`);
    console.log(`    ${error.message}`);
  }
}

export function assert(condition, message = 'Assertion failed') {
  if (!condition) {
    throw new Error(message);
  }
}

export function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

export function assertDeepEqual(actual, expected, message) {
  const actualStr = JSON.stringify(actual);
  const expectedStr = JSON.stringify(expected);
  if (actualStr !== expectedStr) {
    throw new Error(message || `Expected ${expectedStr}, got ${actualStr}`);
  }
}

export function assertThrows(fn, message = 'Expected function to throw') {
  try {
    fn();
    throw new Error(message);
  } catch (error) {
    if (error.message === message) throw error;
    // Expected throw
  }
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Run all tests
async function runTests() {
  console.log('\n\x1b[1mHD Wallet WASM Test Suite\x1b[0m\n');

  try {
    // Import and run test modules
    console.log('\x1b[1mBIP-39 Tests:\x1b[0m');
    await import('./test_bip39.mjs');

    console.log('\n\x1b[1mBIP-32 Tests:\x1b[0m');
    await import('./test_bip32.mjs');

    console.log('\n\x1b[1mTest Vectors:\x1b[0m');
    await import('./test_vectors.mjs');

    console.log('\n\x1b[1mCrypto Tests:\x1b[0m');
    await import('./test_crypto.mjs');

    console.log('\n\x1b[1mExtended Feature Tests:\x1b[0m');
    await import('./test_extended_features.mjs');

    console.log('\n\x1b[1mTransaction Builder Tests:\x1b[0m');
    await import('./test_transactions.mjs');

    console.log('\n\x1b[1mBuild Artifact Browser Compatibility:\x1b[0m');
    await import('./test_bundle_browser_artifact.mjs');

    console.log('\n\x1b[1mAPI Surface Tests:\x1b[0m');
    await import('./test_api_surface.mjs');

    console.log('\n\x1b[1mX.509 Tests:\x1b[0m');
    await import('./test_x509.mjs');

    console.log('\n\x1b[1mAligned Surface Tests:\x1b[0m');
    await import('./test_aligned_surface.mjs');

    console.log('\n\x1b[1mSDN Plugin Compliance Tests:\x1b[0m');
    await import('./test_sdn_plugin_compliance.mjs');

    console.log('\n\x1b[1mIsomorphic Tests:\x1b[0m');
    await import('./test_isomorphic.mjs');

    console.log('\n\x1b[1mEPM Attestation (JCS) Tests:\x1b[0m');
    await import('./test_epm_attestation.mjs');

    console.log('\n\x1b[1mEPM Dual-Curve (secp256k1 + ed25519) Tests:\x1b[0m');
    await import('./test_epm_dual_curve.mjs');

    console.log('\n\x1b[1mLow-Priority Edge Case Tests (L1-L8):\x1b[0m');
    await import('./test_low_edge_cases.mjs');

    console.log('\n\x1b[1mlibp2p PeerID / IPNS Tests:\x1b[0m');
    await import('./test_libp2p.mjs');

  } catch (error) {
    console.error('\nTest suite error:', error.message);
    if (error.message.includes('Cannot find module') || error.message.includes('WASM')) {
      console.log('\nWASM module may not be properly built.');
    }
    process.exit(1);
  }

  // Print summary
  console.log('\n\x1b[1mSummary:\x1b[0m');
  console.log(`  Total: ${totalTests}`);
  console.log(`  \x1b[32mPassed: ${passedTests}\x1b[0m`);
  if (failedTests > 0) {
    console.log(`  \x1b[31mFailed: ${failedTests}\x1b[0m`);
    console.log('\n\x1b[1mFailures:\x1b[0m');
    for (const { name, error } of failures) {
      console.log(`  - ${name}: ${error.message}`);
    }
    process.exit(1);
  }

  console.log('\n\x1b[32mAll tests passed!\x1b[0m\n');
}

runTests();
