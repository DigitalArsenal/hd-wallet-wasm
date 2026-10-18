/**
 * The page's one-use reply key for sealed-field opening.
 *
 * The wallet returns each opened field sealed to this X25519 key with the SDN
 * Unified ECIES field cipher, so the relay that carries the result never holds
 * a plaintext:
 *
 *   Z        = X25519(replyPrivate, walletReplyEphemeral)
 *   K        = HKDF-SHA256(Z, salt = none, info = "sdn-wallet-reply/v1")
 *   fieldKey = HKDF-SHA256(K, "flatbuffers-field" || BE16(index) || BE32(0))
 *   fieldIV  = HKDF-SHA256(K, "flatbuffers-iv"    || BE16(index) || BE32(0))
 *   value    = AES-256-CTR(fieldKey, fieldIV) XOR replyCiphertext
 *
 * The private key is a non-extractable Web Crypto key; it is dropped after
 * the one reply it opens.
 */

const REPLY_CONTEXT = new TextEncoder().encode('sdn-wallet-reply/v1');
const FIELD_LABEL = new TextEncoder().encode('flatbuffers-field');
const IV_LABEL = new TextEncoder().encode('flatbuffers-iv');

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(text) {
  return Uint8Array.from(text.match(/../gu), (pair) => Number.parseInt(pair, 16));
}

function fieldInfo(label, index) {
  const info = new Uint8Array(label.length + 6);
  info.set(label);
  info[label.length] = index >> 8;
  info[label.length + 1] = index & 0xff;
  return info;
}

async function hkdf(subtle, ikm, info, bits) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({
    hash: 'SHA-256', info, name: 'HKDF', salt: new Uint8Array(0),
  }, key, bits));
}

/** A fresh reply key: its public half (hex) and a one-use opener. */
export async function createReplyKey(cryptoObject) {
  const subtle = cryptoObject?.subtle;
  if (!subtle) throw new Error('Web Crypto is unavailable');
  const pair = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicKey = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  if (publicKey.length !== 32) throw new Error('X25519 public key is not 32 bytes');
  let privateKey = pair.privateKey;
  return Object.freeze({
    publicKeyHex: hex(publicKey),
    /** Each reply ciphertext, in order, opened to its bytes. */
    async open(ephemeralPublicKeyHex, ciphertexts) {
      if (!privateKey) throw new Error('reply key already used');
      const own = privateKey;
      privateKey = null;
      const peer = await subtle.importKey('raw', fromHex(ephemeralPublicKeyHex), { name: 'X25519' }, false, []);
      const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, own, 256));
      const master = await hkdf(subtle, shared, REPLY_CONTEXT, 256);
      shared.fill(0);
      try {
        return await Promise.all(ciphertexts.map(async (ciphertext, index) => {
          if (ciphertext === null) return null;
          const fieldKey = await hkdf(subtle, master, fieldInfo(FIELD_LABEL, index), 256);
          const counter = await hkdf(subtle, master, fieldInfo(IV_LABEL, index), 128);
          const key = await subtle.importKey('raw', fieldKey, 'AES-CTR', false, ['decrypt']);
          fieldKey.fill(0);
          return new Uint8Array(await subtle.decrypt({ counter, length: 128, name: 'AES-CTR' }, key, ciphertext));
        }));
      } finally {
        master.fill(0);
      }
    },
  });
}
