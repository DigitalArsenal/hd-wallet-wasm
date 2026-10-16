/**
 * The contact card: a signed Space Data Standards $EPM record.
 *
 * buildContactEpm() assembles the EPM fields for the current account (profile,
 * the Ed25519 Signing and X25519 Encryption keys, the /p2p/ peer address and
 * chain proofs for the account's three addresses) and signs it with the
 * account's Ed25519 key through hd-wallet-wasm's signEPMContent.
 * contactFromEpm() is the import side: it accepts a decoded EPM only when its
 * signature, peer address, chain proofs and photo all check out.
 *
 * FlatBuffer encoding and decoding live in envelopes.js (encodeEpm /
 * decodeEpm); this module works on the plain field object, and
 * contactCardBytes / contactFromCardBytes join the two. Every private key
 * arrives through a callback that zeroes it afterwards.
 */

import {
  buildAllChainProofs,
  buildCanonicalPayload,
  signEPMContent,
  verifyChainProof,
  verifyEPMSignature,
} from 'hd-wallet-wasm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';

import { generateAddressForCoin, generateSolAddress } from './address-derivation.js';
import { peerIdFromEd25519, toHex } from './identity-keys.js';
import { inspectPhotoBytes } from '../origin-app/photo.mjs';

export const KEY_TYPE_SIGNING = 0;
export const KEY_TYPE_ENCRYPTION = 1;
export const ENTITY_TYPE_USER = 0;

/** The largest PHOTO accepted from someone else's card (decoded bytes). */
export const MAX_IMPORTED_PHOTO_BYTES = 64 * 1024;
/** The largest PHOTO this wallet puts in its own card (decoded bytes). */
export const MAX_OWN_PHOTO_BYTES = 32 * 1024;

export const CONTACT_CARD_INVALID = "This contact card's signature is not valid.";
export const CONTACT_CARD_NOT_EPM = 'This is not an SDS contact card (.epm).';

const PHOTO_DATA_URL = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})$/u;
const HEX64 = /^[0-9a-f]{64}$/u;

export class ContactCardError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ContactCardError';
    this.code = code;
  }
}

/** The profile fields, in display order, with their labels. */
export const PROFILE_FIELDS = Object.freeze([
  Object.freeze({ id: 'name', label: 'Name' }),
  Object.freeze({ id: 'jobTitle', label: 'Job title' }),
  Object.freeze({ id: 'organization', label: 'Organization' }),
  Object.freeze({ id: 'email', label: 'Email', type: 'email' }),
  Object.freeze({ id: 'phone', label: 'Phone', type: 'tel' }),
  Object.freeze({ id: 'street', label: 'Street' }),
  Object.freeze({ id: 'city', label: 'City' }),
  Object.freeze({ id: 'region', label: 'State or region' }),
  Object.freeze({ id: 'postalCode', label: 'Postal code' }),
  Object.freeze({ id: 'country', label: 'Country' }),
]);

const PROFILE_IDS = PROFILE_FIELDS.map((field) => field.id);
const MAX_NAME_LENGTH = 128;

// Characters a one-line profile field never needs: C0/C1 controls, the
// U+2028/U+2029 line separators (Go's encoding/json escapes them, so a card
// holding one verifies here but not on an SDN node), the bidi overrides and
// isolates (which can make a name or a file name read backwards) and BOM.
// Tabs and line breaks become spaces.
const FIELD_BREAKS = /[\t\n\r\v\f]+/gu;
const FIELD_UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/gu;

/** One line of profile text: unsafe characters removed, trimmed, at most `max` characters. */
export function cleanText(value, max = 256) {
  if (typeof value !== 'string') return '';
  return value.replace(FIELD_BREAKS, ' ').replace(FIELD_UNSAFE, '').trim().slice(0, max).trim();
}

/** A clean profile object: every known field as a cleaned string, nothing else. */
export function normalizeProfile(value) {
  const source = value && typeof value === 'object' ? value : {};
  const profile = {};
  for (const id of PROFILE_IDS) {
    profile[id] = cleanText(source[id], id === 'name' ? MAX_NAME_LENGTH : 256);
  }
  const photo = typeof source.photo === 'string' ? source.photo : '';
  profile.photo = isOwnPhotoDataUrl(photo) ? photo : '';
  return profile;
}

/** Street, City, State or region, Postal code and Country on one line. */
export function joinAddress(profile) {
  return ['street', 'city', 'region', 'postalCode', 'country']
    .map((id) => (typeof profile?.[id] === 'string' ? profile[id].trim() : ''))
    .filter(Boolean)
    .join(', ');
}

/** Initials for an avatar: the first letters of the first and last words. */
export function initialsOf(name) {
  const words = String(name ?? '').trim().split(/\s+/u).filter(Boolean);
  if (words.length === 0) return '';
  const first = [...words[0]][0] ?? '';
  const last = words.length > 1 ? ([...words[words.length - 1]][0] ?? '') : '';
  return (first + last).toUpperCase();
}

/** RFC 4514 attribute-value escaping. */
export function escapeDnValue(value) {
  let text = String(value ?? '');
  text = text.replace(/[\\,+"<>;=]/gu, (ch) => `\\${ch}`);
  text = text.replace(/\u0000/gu, '\\00');
  if (text.startsWith(' ') || text.startsWith('#')) text = `\\${text}`;
  if (text.endsWith(' ') && !text.endsWith('\\ ')) text = `${text.slice(0, -1)}\\ `;
  return text;
}

export function buildDn(profile) {
  const name = String(profile?.name ?? '').trim();
  const org = String(profile?.organization ?? '').trim();
  if (!name) return '';
  return org ? `CN=${escapeDnValue(name)},O=${escapeDnValue(org)}` : `CN=${escapeDnValue(name)}`;
}

/** Lowercase ASCII slug with `-` separators, at most 48 characters. */
export function slugify(value) {
  const ascii = String(value ?? '')
    .normalize('NFKD')
    .replace(/[̀-ͯ]/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '');
  return ascii.slice(0, 48).replace(/-+$/u, '');
}

export function contactCardFileName(name) {
  return `${slugify(name) || 'contact'}.epm`;
}

function base64ToBytes(text) {
  const binary = globalThis.atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** bytes → base64, chunked so large photos do not overflow the call stack. */
export function bytesToBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return globalThis.btoa(binary);
}

/**
 * Decode and check a `data:image/(jpeg|png|webp);base64,` photo. Returns the
 * image bytes, or null when the value is not an acceptable photo.
 */
export function photoBytesFromDataUrl(value, maximumBytes = MAX_IMPORTED_PHOTO_BYTES) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximumBytes / 3) * 4 + 32) return null;
  const match = PHOTO_DATA_URL.exec(value);
  if (!match) return null;
  let bytes;
  try {
    bytes = base64ToBytes(match[2]);
  } catch {
    return null;
  }
  if (bytes.length === 0 || bytes.length > maximumBytes) return null;
  try {
    const inspected = inspectPhotoBytes(bytes);
    if (inspected.type !== `image/${match[1]}`) return null;
    return inspected.bytes;
  } catch {
    return null;
  }
}

export function isOwnPhotoDataUrl(value) {
  return photoBytesFromDataUrl(value, MAX_OWN_PHOTO_BYTES) !== null
    && String(value).startsWith('data:image/jpeg;base64,');
}

export function jpegDataUrl(bytes) {
  return `data:image/jpeg;base64,${bytesToBase64(bytes)}`;
}

/**
 * The account's contact card as a signed EPM field object.
 *
 * @param {object} wasm  the wallet's hd-wallet-wasm instance
 * @param {object} options
 * @param {object} options.profile     normalizeProfile() fields (photo optional)
 * @param {{edPub: Uint8Array, xPub: Uint8Array, peerId: string}} options.identity
 * @param {object} [options.addresses] { btc|eth|sol: { address, publicKey, path } }
 * @param {(path: string, fn: (key: Uint8Array) => any) => any} [options.withChainKey]
 *        Derives one chain private key, runs fn, zeroes it.
 * @param {(fn: (key: Uint8Array) => any) => any} options.withEdKey
 *        Runs fn with the account's Ed25519 key and zeroes it.
 * @param {() => number} [options.now]
 */
export function buildContactEpm(wasm, {
  profile: rawProfile,
  identity,
  addresses = null,
  withChainKey = null,
  withEdKey,
  now = Date.now,
}) {
  if (!identity?.edPub || !identity?.xPub || !identity?.peerId) throw new Error('No identity keys');
  if (typeof withEdKey !== 'function') throw new Error('No signing key');
  const profile = normalizeProfile(rawProfile);
  const edHex = toHex(identity.edPub);
  const xHex = toHex(identity.xPub);

  const epm = {};
  if (profile.name) epm.LEGAL_NAME = profile.name;
  const dn = buildDn(profile);
  if (dn) epm.DN = dn;
  if (profile.jobTitle) epm.JOB_TITLE = profile.jobTitle;
  if (profile.email) epm.EMAIL = profile.email;
  if (profile.phone) epm.TELEPHONE = profile.phone;
  const address = {};
  if (profile.street) address.STREET = profile.street;
  if (profile.city) address.LOCALITY = profile.city;
  if (profile.region) address.REGION = profile.region;
  if (profile.postalCode) address.POSTAL_CODE = profile.postalCode;
  if (profile.country) address.COUNTRY = profile.country;
  if (Object.keys(address).length) epm.ADDRESS = address;
  if (profile.photo) epm.PHOTO = profile.photo;
  epm.KEYS = [
    { PUBLIC_KEY: edHex, KEY_TYPE: KEY_TYPE_SIGNING, ALGORITHM: 'ed25519', ENCODING: 'raw-ed25519' },
    { PUBLIC_KEY: xHex, KEY_TYPE: KEY_TYPE_ENCRYPTION, ALGORITHM: 'x25519' },
  ];
  epm.MULTIFORMAT_ADDRESS = [`/p2p/${identity.peerId}`];
  epm.ENTITY_TYPE = ENTITY_TYPE_USER;

  if (addresses && typeof withChainKey === 'function') {
    // The card never carries the account xpub: anyone holding the card could
    // list every address of the account with it. The proofs bind the Ed25519
    // and X25519 keys, which is all a reader checks.
    const canonicalPayload = buildCanonicalPayload({
      xpub: '',
      signingPubKeyHex: edHex,
      encryptionPubKeyHex: xHex,
      issuedAt: Math.floor(now() / 1000),
    });
    epm.CHAIN_PROOFS = buildChainProofs(wasm, { canonicalPayload, addresses, withChainKey });
  }

  const signed = withEdKey((edPriv) => signEPMContent(wasm, epm, edPriv));
  epm.SIGNATURE = signed.signature;
  epm.SIGNATURE_TIMESTAMP = signed.timestamp;
  epm.SIGNATURE_ALGORITHM = 'ed25519';
  return epm;
}

function buildChainProofs(wasm, { canonicalPayload, addresses, withChainKey }) {
  const params = { canonicalPayload };
  const chains = [
    ['bitcoin', 'btc'],
    ['ethereum', 'eth'],
    ['solana', 'sol'],
  ];
  // Each key is derived inside its own withChainKey scope and zeroed when the
  // scope ends; the proofs are built in the innermost scope.
  const run = (index) => {
    if (index === chains.length) return buildAllChainProofs(wasm, params);
    const [name, chain] = chains[index];
    const entry = addresses[chain];
    if (!entry?.address || !entry?.publicKey || !entry?.path) return run(index + 1);
    return withChainKey(entry.path, (privateKey) => {
      params[name] = {
        address: entry.address,
        publicKeyHex: toHex(entry.publicKey),
        privateKey,
        keyPath: entry.path,
      };
      try {
        return run(index + 1);
      } finally {
        delete params[name];
      }
    });
  };
  return run(0);
}

function keyTypeOf(key) {
  const value = key?.KEY_TYPE;
  if (value === KEY_TYPE_SIGNING || value === 'Signing') return 'Signing';
  if (value === KEY_TYPE_ENCRYPTION || value === 'Encryption') return 'Encryption';
  return null;
}

function hexKey(value) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return HEX64.test(text) ? text : null;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function trimmed(value, max = 256) {
  return cleanText(value, max);
}

function proofAddressMatches(proof, publicKey) {
  const chain = String(proof.CHAIN ?? '').toLowerCase();
  const address = String(proof.ADDRESS ?? '');
  try {
    if (chain === 'bitcoin') return generateAddressForCoin(publicKey, 0) === address;
    if (chain === 'ethereum') return generateAddressForCoin(publicKey, 60).toLowerCase() === address.toLowerCase();
    if (chain === 'solana') return generateSolAddress(publicKey) === address;
  } catch {
    return false;
  }
  return false;
}

const STRICT_HEX = /^(?:[0-9a-f]{2})+$/u;
const textEncoder = new TextEncoder();

function strictHex(value) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return STRICT_HEX.test(text) ? hexToBytes(text) : null;
}

function compactSize(length) {
  if (length < 253) return [length];
  if (length <= 0xffff) return [253, length & 0xff, length >>> 8];
  return [254, length & 0xff, (length >>> 8) & 0xff, (length >>> 16) & 0xff, length >>> 24];
}

/**
 * Check a secp256k1 chain proof's signature a second time, outside the WASM.
 *
 * hd-wallet-wasm up to 2.1.0 verifies these proofs by recovering the key, and
 * a failed recovery returned the PREVIOUS recovery's key as if it had
 * succeeded (SEC-002). A card could therefore list someone else's real proof
 * (whose key is then recovered) and, after it, a proof with a garbage
 * signature claiming that person's address for the card's own key: the WASM
 * check passed. This independent ECDSA verify (noble, over the chain's
 * signed-message digest) does not depend on that state. Proofs on other
 * algorithms return true here and rely on the WASM check alone.
 */
function secpProofSignatureVerifies(proof) {
  const algorithm = proof?.ALGORITHM;
  const bitcoin = algorithm === 'secp256k1-compact-bitcoin';
  const ethereum = algorithm === 'secp256k1-compact-ethereum';
  if (!bitcoin && !ethereum) return true;
  const signature = strictHex(proof.SIGNATURE);
  const publicKey = strictHex(proof.PUBLIC_KEY);
  const payload = strictHex(proof.SIGNED_PAYLOAD);
  if (!signature || signature.length !== 65 || !publicKey || publicKey.length !== 33 || !payload) return false;
  if (signature[0] < 27 || signature[0] > 34) return false;
  const digest = ethereum
    ? keccak_256(Uint8Array.from([...textEncoder.encode(`\x19Ethereum Signed Message:\n${payload.length}`), ...payload]))
    : sha256(sha256(Uint8Array.from([...textEncoder.encode('\x18Bitcoin Signed Message:\n'), ...compactSize(payload.length), ...payload])));
  try {
    const compact = signature.subarray(1);
    if (!secp256k1.verify(compact, digest, publicKey, { lowS: ethereum, prehash: false })) return false;
    // The header's recovery id must name this key too, as the chains check it.
    const recovered = secp256k1.Signature.fromCompact(compact)
      .addRecoveryBit((signature[0] - 27) & 3)
      .recoverPublicKey(digest)
      .toRawBytes(true);
    return recovered.length === publicKey.length && recovered.every((byte, i) => byte === publicKey[i]);
  } catch {
    return false;
  }
}

function proofBindsKey(proof, edHex) {
  try {
    const payload = JSON.parse(new TextDecoder().decode(hexToBytes(String(proof.SIGNED_PAYLOAD))));
    return String(payload?.signing_pubkey_hex ?? '').toLowerCase() === edHex;
  } catch {
    return false;
  }
}

const CHAIN_SLUGS = Object.freeze({ bitcoin: 'btc', ethereum: 'eth', solana: 'sol' });

/**
 * Accept a decoded $EPM as a contact.
 *
 * Requirements: an Ed25519 Signing key whose signature over the card verifies,
 * and a `/p2p/<id>` address whose id is that key's peer ID. Only chain proofs
 * that verify, that name an address derived from their key and that bind this
 * card's signing key are kept. A photo is kept only when it is a
 * jpeg/png/webp data URL of at most 64 KiB that passes the byte inspector.
 *
 * @returns {object} the contact record (public data only)
 * @throws {ContactCardError}
 */
export function contactFromEpm(wasm, epm) {
  if (!epm || typeof epm !== 'object' || !Array.isArray(epm.KEYS)) {
    throw new ContactCardError(CONTACT_CARD_NOT_EPM, 'NOT_EPM');
  }
  const signingKey = epm.KEYS.find((key) => keyTypeOf(key) === 'Signing'
    && (!key.ALGORITHM || String(key.ALGORITHM).toLowerCase() === 'ed25519')
    && hexKey(key.PUBLIC_KEY));
  if (!signingKey) throw new ContactCardError(CONTACT_CARD_INVALID, 'NO_SIGNING_KEY');
  const edHex = hexKey(signingKey.PUBLIC_KEY);
  const edPub = hexToBytes(edHex);
  let valid = false;
  try {
    valid = verifyEPMSignature(wasm, epm, edPub, { curve: 'ed25519' });
  } catch {
    valid = false;
  }
  if (!valid) throw new ContactCardError(CONTACT_CARD_INVALID, 'BAD_SIGNATURE');

  const peerId = peerIdFromEd25519(wasm, edPub);
  const addresses = Array.isArray(epm.MULTIFORMAT_ADDRESS) ? epm.MULTIFORMAT_ADDRESS : [];
  const p2p = addresses
    .map((value) => /^\/p2p\/(\w+)$/u.exec(String(value ?? '').trim()))
    .filter(Boolean)
    .map((match) => match[1]);
  if (!p2p.includes(peerId)) throw new ContactCardError(CONTACT_CARD_INVALID, 'PEER_MISMATCH');

  const encryptionKey = epm.KEYS.find((key) => keyTypeOf(key) === 'Encryption'
    && (!key.ALGORITHM || String(key.ALGORITHM).toLowerCase() === 'x25519')
    && hexKey(key.PUBLIC_KEY));

  const verified = {};
  for (const proof of Array.isArray(epm.CHAIN_PROOFS) ? epm.CHAIN_PROOFS : []) {
    const chain = CHAIN_SLUGS[String(proof?.CHAIN ?? '').toLowerCase()];
    if (!chain || verified[chain]) continue;
    try {
      if (!verifyChainProof(wasm, proof)) continue;
      if (!secpProofSignatureVerifies(proof)) continue;
      const publicKey = hexToBytes(String(proof.PUBLIC_KEY));
      if (!proofAddressMatches(proof, publicKey)) continue;
      if (!proofBindsKey(proof, edHex)) continue;
      verified[chain] = String(proof.ADDRESS);
    } catch {
      // A malformed proof is dropped, not fatal.
    }
  }

  const photo = photoBytesFromDataUrl(epm.PHOTO, MAX_IMPORTED_PHOTO_BYTES) ? String(epm.PHOTO) : '';
  const address = epm.ADDRESS && typeof epm.ADDRESS === 'object' ? epm.ADDRESS : {};
  const organization = /(?:^|,)O=((?:\\.|[^,\\])*)/u.exec(String(epm.DN ?? ''))?.[1]?.replace(/\\(.)/gu, '$1') ?? '';
  const name = trimmed(epm.LEGAL_NAME, MAX_NAME_LENGTH)
    || trimmed([epm.GIVEN_NAME, epm.FAMILY_NAME].filter((part) => typeof part === 'string').join(' '), MAX_NAME_LENGTH);

  return Object.freeze({
    peerId,
    name,
    signingKey: edHex,
    encryptionKey: encryptionKey ? hexKey(encryptionKey.PUBLIC_KEY) : null,
    jobTitle: trimmed(epm.JOB_TITLE),
    organization: trimmed(organization),
    email: trimmed(epm.EMAIL),
    phone: trimmed(epm.TELEPHONE),
    street: trimmed(address.STREET),
    city: trimmed(address.LOCALITY),
    region: trimmed(address.REGION),
    postalCode: trimmed(address.POSTAL_CODE),
    country: trimmed(address.COUNTRY),
    photo,
    addresses: Object.freeze(verified),
    signedAt: Number.isFinite(Number(epm.SIGNATURE_TIMESTAMP)) ? Number(epm.SIGNATURE_TIMESTAMP) : 0,
  });
}

/**
 * A contact card file (`.epm` bytes) as a contact: decoded with the envelope
 * codec (`codec.decodeEpm`, envelopes.js), then checked by contactFromEpm.
 * Bytes that are not a well-formed $EPM give CONTACT_CARD_NOT_EPM.
 *
 * @throws {ContactCardError}
 */
export function contactFromCardBytes(wasm, codec, bytes) {
  let epm;
  try {
    epm = codec.decodeEpm(wasm, bytes);
  } catch {
    throw new ContactCardError(CONTACT_CARD_NOT_EPM, 'NOT_EPM');
  }
  return contactFromEpm(wasm, epm);
}

/** The account's contact card file: buildContactEpm fields, encoded by `codec.encodeEpm`. */
export function contactCardBytes(wasm, codec, options) {
  return codec.encodeEpm(wasm, buildContactEpm(wasm, options));
}

/**
 * A stored contact list with a new card merged in: the same peer ID replaces
 * the old entry; the list stays sorted by name.
 */
export function upsertContact(contacts, contact) {
  const list = Array.isArray(contacts) ? contacts.filter((entry) => entry?.peerId !== contact.peerId) : [];
  list.push({ ...contact, addresses: { ...contact.addresses } });
  return sortContacts(list);
}

export function sortContacts(contacts) {
  return [...contacts].sort((a, b) => {
    const left = (a.name || a.peerId || '').toLocaleLowerCase();
    const right = (b.name || b.peerId || '').toLocaleLowerCase();
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

/** A stored contact, re-checked on load: only well-formed public fields survive. */
export function sanitizeStoredContact(value) {
  if (!value || typeof value !== 'object') return null;
  const peerId = typeof value.peerId === 'string' && /^\w{20,80}$/u.test(value.peerId) ? value.peerId : null;
  const signingKey = hexKey(value.signingKey);
  if (!peerId || !signingKey) return null;
  const addresses = {};
  for (const chain of ['btc', 'eth', 'sol']) {
    if (typeof value.addresses?.[chain] === 'string' && value.addresses[chain].length <= 128) {
      addresses[chain] = value.addresses[chain];
    }
  }
  const contact = {
    peerId,
    signingKey,
    encryptionKey: hexKey(value.encryptionKey),
    photo: photoBytesFromDataUrl(value.photo) ? value.photo : '',
    addresses,
    signedAt: Number.isFinite(Number(value.signedAt)) ? Number(value.signedAt) : 0,
  };
  for (const id of PROFILE_IDS) contact[id] = trimmed(value[id]);
  return contact;
}
