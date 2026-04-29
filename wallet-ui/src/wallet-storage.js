/**
 * Wallet Storage Module
 *
 * Industry-standard implementation for securely storing wallet credentials
 * using WebAuthn PRF extension or PIN-based encryption.
 *
 * Based on best practices from:
 * - Yubico WebAuthn PRF Developer Guide
 * - wwWallet FUNKE implementation
 * - W3C WebAuthn PRF Extension specification
 *
 * @module wallet-storage
 */

import initHDWallet from 'hd-wallet-wasm';

// =============================================================================
// Storage Keys
// =============================================================================

const STORAGE_PREFIX = 'wallet_storage_';
const METADATA_KEY = `${STORAGE_PREFIX}metadata`;
const ENCRYPTED_DATA_KEY = `${STORAGE_PREFIX}encrypted`;
const PASSKEY_CREDENTIAL_KEY = `${STORAGE_PREFIX}passkey_credential`;

// Version for future migrations
const STORAGE_VERSION = 3;

// AES-GCM standard IV size (96-bit)
const AES_GCM_IV_LENGTH = 12;

// 6-digit PINs have low entropy; PBKDF2 must be expensive to slow offline brute force.
// (This is still not a substitute for rate-limiting when an attacker can query online.)
const PIN_PBKDF2_ITERATIONS = 600000;
const LEGACY_PIN_PBKDF2_ITERATIONS = 100000;
const AES_GCM_TAG_LENGTH = 16;

let walletPromise = null;

function getWallet() {
  if (!walletPromise) walletPromise = initHDWallet();
  return walletPromise;
}

function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error('Expected byte array');
}

// =============================================================================
// Storage Method Enum
// =============================================================================

export const StorageMethod = {
  NONE: 'none',
  PIN: 'pin',
  PASSKEY: 'passkey'
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate cryptographically secure random bytes
 */
async function generateRandomBytes(length) {
  const wallet = await getWallet();
  return wallet.utils.getRandomBytes(length);
}

// =============================================================================
// Key Derivation (HKDF - Industry Standard)
// =============================================================================

/**
 * Derive encryption key using HKDF (HMAC-based Key Derivation Function)
 * This is the industry-standard approach recommended by Yubico and others.
 *
 * @param {Uint8Array} inputKeyMaterial - The input key material (from PRF or PIN hash)
 * @param {Uint8Array} salt - Salt for HKDF
 * @param {string} info - Context info string
 * @param {number} length - Desired key length in bytes
 * @returns {Promise<Uint8Array>} Derived key
 */
async function hkdfDerive(inputKeyMaterial, salt, info, length) {
  const encoder = new TextEncoder();
  const wallet = await getWallet();
  const infoBytes = typeof info === 'string' ? encoder.encode(info) : asUint8Array(info);
  return wallet.utils.hkdf(asUint8Array(inputKeyMaterial), asUint8Array(salt), infoBytes, length);
}

/**
 * Derive encryption key from key material (HKDF).
 */
async function deriveEncryptionKey(keyMaterial, context) {
  const salt = new TextEncoder().encode(`wallet-storage-v${STORAGE_VERSION}`);

  const encryptionKey = await hkdfDerive(
    keyMaterial,
    salt,
    `${context}-encryption-key`,
    32
  );

  return encryptionKey;
}

/**
 * Legacy: v1/v2 storage used a deterministic IV derived via HKDF.
 * This exists only to decrypt and upgrade old stored blobs.
 */
async function deriveLegacyKeyAndIV(keyMaterial, context, version) {
  const salt = new TextEncoder().encode(`wallet-storage-v${version}`);
  const encryptionKey = await hkdfDerive(
    keyMaterial,
    salt,
    `${context}-encryption-key`,
    32
  );
  const iv = await hkdfDerive(
    keyMaterial,
    salt,
    `${context}-encryption-iv`,
    AES_GCM_IV_LENGTH
  );
  return { encryptionKey, iv };
}

// =============================================================================
// PIN-Based Encryption
// =============================================================================

/**
 * Derive key material from a 6-digit PIN
 * Uses PBKDF2 for additional security against brute-force attacks
 */
async function deriveKeyFromPIN(pin, storedSalt, iterations = PIN_PBKDF2_ITERATIONS) {
  if (!/^\d{6}$/.test(pin)) {
    throw new Error('PIN must be exactly 6 digits');
  }

  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);

  // Use stored salt or generate new one
  const salt = storedSalt || await generateRandomBytes(16);
  const wallet = await getWallet();

  return {
    keyMaterial: wallet.utils.pbkdf2(pinBytes, salt, iterations, 32),
    salt
  };
}

// =============================================================================
// WebAuthn PRF Extension
// =============================================================================

/**
 * Check if WebAuthn/Passkeys are supported
 */
export function isPasskeySupported() {
  return !!(
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential === 'function'
  );
}

/**
 * Check if PRF extension is likely supported
 * Note: Full support detection requires actually creating a credential
 */
export async function isPRFLikelySupported() {
  if (!isPasskeySupported()) return false;

  try {
    // Check if platform authenticator is available
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
  } catch {
    return false;
  }
}

/**
 * Generate WebAuthn challenge
 */
async function generateChallenge() {
  return generateRandomBytes(32);
}

/**
 * Create PRF input salts for key derivation
 * Following the recommended pattern from Yubico for key rotation support
 */
function createPRFInputs() {
  const encoder = new TextEncoder();
  return {
    // Primary key derivation salt
    first: encoder.encode('wallet-storage-prf-v2-primary'),
    // Secondary salt for future key rotation support
    second: encoder.encode('wallet-storage-prf-v2-secondary')
  };
}

/**
 * Register a new passkey and derive encryption key material
 *
 * @param {Object} options - Registration options
 * @param {string} options.rpName - Relying party name (e.g., 'My App')
 * @param {string} options.userName - User identifier
 * @param {string} options.userDisplayName - User display name
 * @returns {Promise<{credentialId: string, keyMaterial: Uint8Array, hasPRF: boolean}>}
 */
export async function registerPasskey(options = {}) {
  if (!isPasskeySupported()) {
    throw new Error('Passkeys are not supported on this device');
  }

  const {
    rpName = 'Wallet Storage',
    userName = 'wallet-user',
    userDisplayName = 'Wallet User'
  } = options;

  const challenge = await generateChallenge();
  const userId = await generateRandomBytes(16);
  const prfInputs = createPRFInputs();

  const publicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: rpName,
      id: window.location.hostname
    },
    user: {
      id: userId,
      name: userName,
      displayName: userDisplayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256 (P-256)
      { alg: -257, type: 'public-key' }  // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred' // Changed from 'required' for broader compatibility
    },
    timeout: 60000,
    attestation: 'none',
    extensions: {
      prf: {
        eval: {
          first: prfInputs.first
        }
      }
    }
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });

  // Extract PRF result or fall back to credential ID
  const extensionResults = credential.getClientExtensionResults();
  const prfResult = extensionResults?.prf?.results?.first;

  let keyMaterial;
  let hasPRF = false;

  if (prfResult && prfResult.byteLength > 0) {
    keyMaterial = new Uint8Array(prfResult);
    hasPRF = true;
  } else {
    // PRF not available — derive key material from credential ID + a fixed salt.
    const rawId = new Uint8Array(credential.rawId);
    const salt = new TextEncoder().encode('wallet-storage-credid-fallback-v1');
    keyMaterial = await hkdfDerive(rawId, salt, new Uint8Array(0), 32);
  }

  return {
    credentialId: arrayBufferToBase64(credential.rawId),
    keyMaterial,
    hasPRF
  };
}

/**
 * Authenticate with existing passkey and derive encryption key material
 *
 * @param {string} credentialId - Base64-encoded credential ID
 * @returns {Promise<{keyMaterial: Uint8Array, hasPRF: boolean}>}
 */
export async function authenticatePasskey(credentialId) {
  if (!isPasskeySupported()) {
    throw new Error('Passkeys are not supported on this device');
  }

  const challenge = await generateChallenge();
  const prfInputs = createPRFInputs();
  const credentialIdBytes = base64ToUint8Array(credentialId);

  const publicKeyCredentialRequestOptions = {
    challenge,
    allowCredentials: [{
      id: credentialIdBytes,
      type: 'public-key',
      transports: ['internal', 'hybrid'] // Support both platform and cross-device
    }],
    userVerification: 'required',
    timeout: 60000,
    extensions: {
      prf: {
        eval: {
          first: prfInputs.first
        }
      }
    }
  };

  const assertion = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  });

  // Extract PRF result or fall back to credential ID
  const extensionResults = assertion.getClientExtensionResults();
  const prfResult = extensionResults?.prf?.results?.first;

  let keyMaterial;
  let hasPRF = false;

  if (prfResult && prfResult.byteLength > 0) {
    keyMaterial = new Uint8Array(prfResult);
    hasPRF = true;
  } else {
    // PRF not available — derive key material from credential ID + a fixed salt.
    const rawId = new Uint8Array(assertion.rawId);
    const salt = new TextEncoder().encode('wallet-storage-credid-fallback-v1');
    keyMaterial = await hkdfDerive(rawId, salt, new Uint8Array(0), 32);
  }

  return { keyMaterial, hasPRF };
}

// =============================================================================
// Encryption/Decryption
// =============================================================================

/**
 * Encrypt data using AES-256-GCM
 */
async function encryptData(data, encryptionKey, aad) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));
  const iv = await generateRandomBytes(AES_GCM_IV_LENGTH);
  const wallet = await getWallet();
  const { ciphertext, tag } = wallet.utils.aesGcm.encrypt(
    asUint8Array(encryptionKey),
    plaintext,
    iv,
    aad ? asUint8Array(aad) : new Uint8Array(0)
  );
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  return { iv, ciphertext: sealed };
}

/**
 * Decrypt data using AES-256-GCM
 */
async function decryptData(ciphertext, encryptionKey, iv, aad) {
  const sealed = asUint8Array(ciphertext);
  if (sealed.length <= AES_GCM_TAG_LENGTH) {
    throw new Error('Ciphertext is too short');
  }

  const wallet = await getWallet();
  const plaintext = wallet.utils.aesGcm.decrypt(
    asUint8Array(encryptionKey),
    sealed.subarray(0, sealed.length - AES_GCM_TAG_LENGTH),
    sealed.subarray(sealed.length - AES_GCM_TAG_LENGTH),
    asUint8Array(iv),
    aad ? asUint8Array(aad) : new Uint8Array(0)
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

// =============================================================================
// High-Level Storage API
// =============================================================================

function getAadForMethod(method) {
  // Small AAD to bind ciphertexts to this module + method.
  // (Replay protection against localStorage rollback is not achievable without an external monotonic anchor.)
  return new TextEncoder().encode(`wallet-storage|v${STORAGE_VERSION}|${method}`);
}

/**
 * Get storage metadata
 * @returns {Object|null} Storage metadata or null if no wallet stored
 */
export function getStorageMetadata() {
  try {
    const metadataJson = localStorage.getItem(METADATA_KEY);
    if (!metadataJson) return null;

    const metadata = JSON.parse(metadataJson);
    return {
      method: metadata.method || StorageMethod.NONE,
      timestamp: metadata.timestamp,
      date: new Date(metadata.timestamp).toLocaleDateString(),
      version: metadata.version,
      hasPRF: metadata.hasPRF || false
    };
  } catch {
    return null;
  }
}

/**
 * Check if a wallet is stored
 * @returns {boolean}
 */
export function hasStoredWallet() {
  return getStorageMetadata() !== null;
}

/**
 * Get the storage method used
 * @returns {string} StorageMethod value
 */
export function getStorageMethod() {
  const metadata = getStorageMetadata();
  return metadata?.method || StorageMethod.NONE;
}

/**
 * Store wallet data with PIN encryption
 *
 * @param {string} pin - 6-digit PIN
 * @param {Object} walletData - Data to encrypt and store
 * @returns {Promise<boolean>}
 */
export async function storeWithPIN(pin, walletData) {
  // Derive key from PIN
  const { keyMaterial, salt } = await deriveKeyFromPIN(pin);
  const encryptionKey = await deriveEncryptionKey(keyMaterial, 'pin');

  // Encrypt wallet data
  const aad = getAadForMethod(StorageMethod.PIN);
  const { ciphertext, iv } = await encryptData(walletData, encryptionKey, aad);

  // Store encrypted data
  const encryptedData = {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    salt: arrayBufferToBase64(salt)
  };
  localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify(encryptedData));

  // Store metadata
  const metadata = {
    method: StorageMethod.PIN,
    timestamp: Date.now(),
    version: STORAGE_VERSION
  };
  localStorage.setItem(METADATA_KEY, JSON.stringify(metadata));

  return true;
}

/**
 * Retrieve wallet data with PIN
 *
 * @param {string} pin - 6-digit PIN
 * @returns {Promise<Object>} Decrypted wallet data
 */
export async function retrieveWithPIN(pin) {
  const metadata = getStorageMetadata();
  if (!metadata || metadata.method !== StorageMethod.PIN) {
    throw new Error('No PIN-encrypted wallet found');
  }

  const encryptedJson = localStorage.getItem(ENCRYPTED_DATA_KEY);
  if (!encryptedJson) {
    throw new Error('Encrypted data not found');
  }

  const encryptedData = JSON.parse(encryptedJson);
  const salt = base64ToUint8Array(encryptedData.salt);
  const ciphertext = base64ToUint8Array(encryptedData.ciphertext);
  const iv = encryptedData.iv ? base64ToUint8Array(encryptedData.iv) : null;

  // Derive key from PIN with stored salt
  const { keyMaterial } = await deriveKeyFromPIN(pin, salt, iv ? PIN_PBKDF2_ITERATIONS : LEGACY_PIN_PBKDF2_ITERATIONS);
  const aad = getAadForMethod(StorageMethod.PIN);

  try {
    let walletData;
    if (iv) {
      const encryptionKey = await deriveEncryptionKey(keyMaterial, 'pin');
      walletData = await decryptData(ciphertext, encryptionKey, iv, aad);
    } else {
      // Legacy v1/v2 deterministic-IV storage. Decrypt and upgrade in-place.
      const legacyVersion = metadata.version || 2;
      const { encryptionKey: legacyKey, iv: legacyIv } = await deriveLegacyKeyAndIV(keyMaterial, 'pin', legacyVersion);
      walletData = await decryptData(ciphertext, legacyKey, legacyIv);

      // Upgrade stored blob to v3 (random IV) after successful decrypt.
      const newKey = await deriveEncryptionKey(keyMaterial, 'pin');
      const { ciphertext: newCt, iv: newIv } = await encryptData(walletData, newKey, aad);
      localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify({
        ciphertext: arrayBufferToBase64(newCt),
        iv: arrayBufferToBase64(newIv),
        salt: arrayBufferToBase64(salt)
      }));
      localStorage.setItem(METADATA_KEY, JSON.stringify({
        ...metadata,
        version: STORAGE_VERSION
      }));
    }
    return walletData;
  } catch (e) {
    throw new Error('Invalid PIN or corrupted data');
  }
}

/**
 * Store wallet data with passkey encryption
 *
 * @param {Object} walletData - Data to encrypt and store
 * @param {Object} options - Passkey options
 * @returns {Promise<boolean>}
 */
export async function storeWithPasskey(walletData, options = {}) {
  // Prefer reusing an existing stored passkey credential to avoid creating duplicates.
  let credentialId = null;
  let keyMaterial = null;
  let hasPRF = false;

  try {
    const existing = localStorage.getItem(PASSKEY_CREDENTIAL_KEY);
    if (existing) {
      const parsed = JSON.parse(existing);
      if (parsed?.id) {
        credentialId = parsed.id;
        const auth = await authenticatePasskey(credentialId);
        keyMaterial = auth.keyMaterial;
        hasPRF = auth.hasPRF;
      }
    }
  } catch {
    // Ignore and fall back to registration below.
  }

  if (!keyMaterial) {
    const reg = await registerPasskey(options);
    credentialId = reg.credentialId;
    keyMaterial = reg.keyMaterial;
    hasPRF = reg.hasPRF;
  }

  // Derive encryption key
  const encryptionKey = await deriveEncryptionKey(keyMaterial, 'passkey');

  // Encrypt wallet data
  const aad = getAadForMethod(StorageMethod.PASSKEY);
  const { ciphertext, iv } = await encryptData(walletData, encryptionKey, aad);

  // Store credential info
  const credentialData = {
    id: credentialId,
    hasPRF
  };
  localStorage.setItem(PASSKEY_CREDENTIAL_KEY, JSON.stringify(credentialData));

  // Store encrypted data
  const encryptedData = {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv)
  };
  localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify(encryptedData));

  // Store metadata
  const metadata = {
    method: StorageMethod.PASSKEY,
    timestamp: Date.now(),
    version: STORAGE_VERSION,
    hasPRF
  };
  localStorage.setItem(METADATA_KEY, JSON.stringify(metadata));

  return true;
}

/**
 * Retrieve wallet data with passkey
 *
 * @returns {Promise<Object>} Decrypted wallet data
 */
export async function retrieveWithPasskey() {
  const metadata = getStorageMetadata();
  if (!metadata || metadata.method !== StorageMethod.PASSKEY) {
    throw new Error('No passkey-encrypted wallet found');
  }
  const credentialJson = localStorage.getItem(PASSKEY_CREDENTIAL_KEY);
  if (!credentialJson) {
    throw new Error('Passkey credential not found');
  }

  const credentialData = JSON.parse(credentialJson);

  const encryptedJson = localStorage.getItem(ENCRYPTED_DATA_KEY);
  if (!encryptedJson) {
    throw new Error('Encrypted data not found');
  }

  const encryptedData = JSON.parse(encryptedJson);
  const ciphertext = base64ToUint8Array(encryptedData.ciphertext);
  const iv = encryptedData.iv ? base64ToUint8Array(encryptedData.iv) : null;

  // Authenticate with passkey and get key material
  const { keyMaterial } = await authenticatePasskey(credentialData.id);

  // Derive encryption key
  const aad = getAadForMethod(StorageMethod.PASSKEY);

  try {
    let walletData;
    if (iv) {
      const encryptionKey = await deriveEncryptionKey(keyMaterial, 'passkey');
      walletData = await decryptData(ciphertext, encryptionKey, iv, aad);
    } else {
      // Legacy v1/v2 deterministic-IV storage. Decrypt and upgrade in-place.
      const legacyVersion = metadata.version || 2;
      const { encryptionKey: legacyKey, iv: legacyIv } = await deriveLegacyKeyAndIV(keyMaterial, 'passkey', legacyVersion);
      walletData = await decryptData(ciphertext, legacyKey, legacyIv);

      const newKey = await deriveEncryptionKey(keyMaterial, 'passkey');
      const { ciphertext: newCt, iv: newIv } = await encryptData(walletData, newKey, aad);
      localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify({
        ciphertext: arrayBufferToBase64(newCt),
        iv: arrayBufferToBase64(newIv)
      }));
      localStorage.setItem(METADATA_KEY, JSON.stringify({
        ...metadata,
        version: STORAGE_VERSION,
        hasPRF: true
      }));
    }
    return walletData;
  } catch (e) {
    throw new Error('Passkey authentication failed or data corrupted');
  }
}

/**
 * Clear all stored wallet data
 */
export function clearStorage() {
  localStorage.removeItem(METADATA_KEY);
  localStorage.removeItem(ENCRYPTED_DATA_KEY);
  localStorage.removeItem(PASSKEY_CREDENTIAL_KEY);
}

/**
 * Migrate from old storage format (v1) to new format (v2)
 * Call this on app initialization
 */
export function migrateStorage() {
  // Check for old v1 keys
  const oldPinWallet = localStorage.getItem('encrypted_wallet');
  const oldPasskeyCredential = localStorage.getItem('passkey_credential');
  const oldPasskeyWallet = localStorage.getItem('passkey_wallet');

  // Already migrated or no old data
  if (getStorageMetadata() !== null) return;
  if (!oldPinWallet && !oldPasskeyCredential) return;

  console.log('Migrating wallet storage from legacy format...');

  if (oldPasskeyCredential && oldPasskeyWallet) {
    // Migrate passkey storage
    try {
      const credential = JSON.parse(oldPasskeyCredential);
      const wallet = JSON.parse(oldPasskeyWallet);

      localStorage.setItem(PASSKEY_CREDENTIAL_KEY, JSON.stringify({
        id: credential.id,
        hasPRF: credential.hasPRF || false
      }));

      localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify({
        ciphertext: wallet.ciphertext
      }));

      localStorage.setItem(METADATA_KEY, JSON.stringify({
        method: StorageMethod.PASSKEY,
        timestamp: credential.timestamp || wallet.timestamp || Date.now(),
        // Preserve legacy version so decrypt can derive the correct legacy HKDF salt/IV,
        // then upgrade in-place on first successful retrieval.
        version: credential.version || wallet.version || 2,
        hasPRF: credential.hasPRF || false
      }));

      // Clean up old keys
      localStorage.removeItem('passkey_credential');
      localStorage.removeItem('passkey_wallet');

      console.log('Passkey storage migrated successfully');
    } catch (e) {
      console.error('Failed to migrate passkey storage:', e);
    }
  } else if (oldPinWallet) {
    // Migrate PIN storage - can't fully migrate since we need the salt
    // User will need to re-enter their wallet
    console.log('PIN storage detected but cannot be migrated - user will need to re-login');
    localStorage.removeItem('encrypted_wallet');
  }
}

// =============================================================================
// Export default object for convenience
// =============================================================================

export default {
  StorageMethod,
  isPasskeySupported,
  isPRFLikelySupported,
  getStorageMetadata,
  hasStoredWallet,
  getStorageMethod,
  storeWithPIN,
  retrieveWithPIN,
  storeWithPasskey,
  retrieveWithPasskey,
  clearStorage,
  migrateStorage
};
