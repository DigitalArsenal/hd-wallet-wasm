// The contact card ($EPM) built by contact-card.js with the real WASM signer,
// and the import-side checks a card must pass to become a contact.

import initHDWallet, {
  buildBitcoinChainProof,
  signEPMContent,
  verifyChainProof,
  verifyEPMSignature,
} from 'hd-wallet-wasm';
import { secp256k1 as nobleSecp } from '@noble/curves/secp256k1';
import { describe, expect, it } from 'vitest';

import {
  CONTACT_CARD_INVALID,
  CONTACT_CARD_NOT_EPM,
  buildContactEpm,
  buildDn,
  bytesToBase64,
  contactCardFileName,
  contactFromEpm,
  escapeDnValue,
  normalizeProfile,
  photoBytesFromDataUrl,
  sanitizeStoredContact,
  slugify,
  upsertContact,
} from '../src/contact-card.js';
import {
  accountXpub,
  deriveAccountAddresses,
  deriveIdentity,
  withChainKey,
  withEdKey,
} from '../src/identity-keys.js';

const TEST_PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const OTHER_PHRASE = `${'zoo '.repeat(11)}wrong`;

function jpeg(width = 16, height = 16, padding = 11) {
  const bytes = new Uint8Array(21 + padding);
  bytes.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, height >> 8, height & 0xff, width >> 8, width & 0xff, 0x03]);
  return bytes;
}

function png(width = 4, height = 4) {
  const bytes = new Uint8Array(24);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  bytes.set([0, 0, 0, 13, 73, 72, 68, 82], 8);
  new DataView(bytes.buffer).setUint32(16, width);
  new DataView(bytes.buffer).setUint32(20, height);
  return bytes;
}

const wallet = await initHDWallet();
const sessions = {};

// A stale local hd-wallet-wasm dist (built before the single-hash chain
// proofs) signs Bitcoin/Ethereum proofs it cannot verify. The proof checks
// below need the current runtime; everything else runs either way.
const chainProofsWork = (() => {
  const seed = wallet.mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const node = wallet.hdkey.fromSeed(seed).derivePath("m/44'/0'/0'/0/0");
  const privateKey = node.privateKey();
  try {
    const proof = buildBitcoinChainProof(wallet, {
      address: 'probe',
      publicKeyHex: wallet.utils.encodeHex(node.publicKey()),
      privateKey,
      keyPath: "m/44'/0'/0'/0/0",
      canonicalPayload: '{}',
    });
    return verifyChainProof(wallet, proof);
  } catch {
    return false;
  } finally {
    privateKey.fill(0);
  }
})();

function session(phrase, account = 0) {
  const key = `${phrase}:${account}`;
  if (sessions[key]) return sessions[key];
  const seed = wallet.mnemonic.toSeed(phrase);
  const root = wallet.hdkey.fromSeed(seed);
  sessions[key] = {
    seed,
    root,
    account,
    identity: deriveIdentity(wallet, seed, account),
    addresses: deriveAccountAddresses(wallet, root, account),
  };
  return sessions[key];
}

function card(s, profile = {}) {
  return buildContactEpm(wallet, {
    profile: { name: 'Ada Lovelace', organization: 'Analytical Engines', email: 'ada@example.org', ...profile },
    identity: s.identity,
    accountXpub: accountXpub(s.root, s.account),
    addresses: s.addresses,
    withChainKey: (path, fn) => withChainKey(s.root, path, fn),
    withEdKey: (fn) => withEdKey(wallet, s.seed, s.account, fn),
  });
}

/** Sign an arbitrary EPM field object with a session's Ed25519 key. */
function resign(s, epm) {
  const copy = { ...epm };
  delete copy.SIGNATURE;
  delete copy.SIGNATURE_TIMESTAMP;
  const signed = withEdKey(wallet, s.seed, s.account, (key) => signEPMContent(wallet, copy, key));
  return { ...copy, SIGNATURE: signed.signature, SIGNATURE_TIMESTAMP: signed.timestamp };
}

describe('building the card', () => {
  it('is a signed EPM with the Ed25519 Signing key, the X25519 Encryption key and the /p2p/ address', () => {
    const s = session(TEST_PHRASE);
    const epm = card(s);
    expect(epm.LEGAL_NAME).toBe('Ada Lovelace');
    expect(epm.DN).toBe('CN=Ada Lovelace,O=Analytical Engines');
    expect(epm.EMAIL).toBe('ada@example.org');
    expect(epm.KEYS).toEqual([
      { PUBLIC_KEY: '7c2e79f3a1701fb2a86a2c24a3fdf8634b7aad80886c0c0a526d44d23fe8e19a', KEY_TYPE: 0, ALGORITHM: 'ed25519', ENCODING: 'raw-ed25519' },
      { PUBLIC_KEY: '654f607c4395ac0599a6c38bc34315dd6644f405218daa4ec5318068f008a364', KEY_TYPE: 1, ALGORITHM: 'x25519' },
    ]);
    expect(epm.MULTIFORMAT_ADDRESS).toEqual([`/p2p/${s.identity.peerId}`]);
    expect(epm.SIGNATURE_ALGORITHM).toBe('ed25519');
    expect(verifyEPMSignature(wallet, epm, s.identity.edPub)).toBe(true);
  });

  it.skipIf(!chainProofsWork)('carries verifiable chain proofs for the account addresses', () => {
    const epm = card(session(TEST_PHRASE));
    expect(epm.CHAIN_PROOFS.map((proof) => proof.CHAIN)).toEqual(['bitcoin', 'ethereum', 'solana']);
    for (const proof of epm.CHAIN_PROOFS) expect(verifyChainProof(wallet, proof)).toBe(true);
  });

  it('carries chain proofs and nothing secret', () => {
    const s = session(TEST_PHRASE);
    const epm = card(s);
    expect(epm.CHAIN_PROOFS.map((proof) => proof.CHAIN)).toEqual(['bitcoin', 'ethereum', 'solana']);
    for (const key of epm.KEYS) {
      for (const field of ['XPUB', 'PRIVATE_KEY', 'KEY_PATH', 'KEY_ADDRESS']) expect(key).not.toHaveProperty(field);
    }
    const text = JSON.stringify(epm);
    expect(text).not.toMatch(/xprv|PRIVATE_KEY/u);
    expect(text).not.toContain(TEST_PHRASE);
  });

  it('escapes the DN per RFC 4514 and names the file from a slug', () => {
    expect(escapeDnValue('Smith, John')).toBe('Smith\\, John');
    expect(escapeDnValue(' #lead')).toBe('\\ #lead');
    expect(escapeDnValue('a+b="c"<d>;')).toBe('a\\+b\\=\\"c\\"\\<d\\>\\;');
    expect(buildDn({ name: 'Ada', organization: 'X, Inc.' })).toBe('CN=Ada,O=X\\, Inc.');
    expect(buildDn({ name: '' })).toBe('');
    expect(slugify('Ada Lovelace')).toBe('ada-lovelace');
    expect(slugify('Ünïcödé — Name!')).toBe('unicode-name');
    expect(slugify('x'.repeat(80))).toHaveLength(48);
    expect(contactCardFileName('Ada Lovelace')).toBe('ada-lovelace.epm');
    expect(contactCardFileName('')).toBe('contact.epm');
  });

  it('keeps only its own 192px JPEG photo (≤ 32 KiB) in the profile', () => {
    const small = `data:image/jpeg;base64,${bytesToBase64(jpeg())}`;
    expect(normalizeProfile({ photo: small }).photo).toBe(small);
    expect(normalizeProfile({ photo: `data:image/png;base64,${bytesToBase64(png())}` }).photo).toBe('');
    expect(normalizeProfile({ photo: `data:image/jpeg;base64,${bytesToBase64(jpeg(16, 16, 40 * 1024))}` }).photo).toBe('');
    expect(normalizeProfile({ photo: 'https://example.org/me.jpg' }).photo).toBe('');
  });
});

describe('importing a card', () => {
  it('accepts a signed card', () => {
    const s = session(TEST_PHRASE);
    const contact = contactFromEpm(wallet, card(s));
    expect(contact.peerId).toBe(s.identity.peerId);
    expect(contact.name).toBe('Ada Lovelace');
    expect(contact.organization).toBe('Analytical Engines');
    expect(contact.encryptionKey).toBe('654f607c4395ac0599a6c38bc34315dd6644f405218daa4ec5318068f008a364');
    expect(contact.addresses.sol).toBe(s.addresses.sol.address);
  });

  it.skipIf(!chainProofsWork)('keeps the addresses of every verified chain proof', () => {
    const s = session(TEST_PHRASE);
    const contact = contactFromEpm(wallet, card(s));
    expect(contact.addresses).toEqual({
      btc: s.addresses.btc.address,
      eth: s.addresses.eth.address,
      sol: s.addresses.sol.address,
    });
  });

  it('rejects a tampered field', () => {
    const epm = { ...card(session(TEST_PHRASE)), LEGAL_NAME: 'Mallory' };
    expect(() => contactFromEpm(wallet, epm)).toThrow(CONTACT_CARD_INVALID);
  });

  it('rejects a card whose /p2p/ peer ID is not its signing key', () => {
    const a = session(TEST_PHRASE);
    const b = session(OTHER_PHRASE);
    const epm = resign(a, { ...card(a), MULTIFORMAT_ADDRESS: [`/p2p/${b.identity.peerId}`] });
    expect(verifyEPMSignature(wallet, epm, a.identity.edPub)).toBe(true);
    expect(() => contactFromEpm(wallet, epm)).toThrow(CONTACT_CARD_INVALID);
  });

  it('rejects something that is not an EPM', () => {
    expect(() => contactFromEpm(wallet, null)).toThrow(CONTACT_CARD_NOT_EPM);
    expect(() => contactFromEpm(wallet, { LEGAL_NAME: 'x' })).toThrow(CONTACT_CARD_NOT_EPM);
  });

  it('drops chain proofs copied from someone else and keeps the signature check', () => {
    const a = session(TEST_PHRASE);
    const b = session(OTHER_PHRASE);
    // b's proofs verify on their own, but bind b's signing key, not a's.
    const epm = resign(a, { ...card(a), CHAIN_PROOFS: card(b).CHAIN_PROOFS });
    const contact = contactFromEpm(wallet, epm);
    expect(contact.addresses).toEqual({});
  });

  it.skipIf(!chainProofsWork)('drops a forged proof that follows someone else\'s real one (SEC-002 stale recovery)', () => {
    const a = session(TEST_PHRASE);
    const b = session(OTHER_PHRASE);
    // hd-wallet-wasm up to 2.1.0: a recovery that fails hands back the
    // previous recovery's key (how often depends on the WASM heap). This
    // wallet does that every time, so the test does not depend on the heap.
    let last = null;
    const secp = wallet.curves.secp256k1;
    const stale = {
      ...wallet,
      curves: {
        ...wallet.curves,
        secp256k1: {
          ...secp,
          recover(digest, signature, recoveryId) {
            try {
              nobleSecp.Signature.fromCompact(signature).addRecoveryBit(recoveryId).recoverPublicKey(digest);
            } catch (error) {
              // No key recovers from this signature: hand back the last one.
              if (!last) throw error;
              return last;
            }
            last = secp.recover(digest, signature, recoveryId);
            return last;
          },
        },
      },
    };
    const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    const text = (h) => new TextDecoder().decode(Uint8Array.from(h.match(/../gu), (pair) => Number.parseInt(pair, 16)));
    const victim = card(b).CHAIN_PROOFS;
    let noPointR = null;
    for (let r = 1n; !noPointR; r += 1n) {
      try {
        nobleSecp.ProjectivePoint.fromHex(`02${r.toString(16).padStart(64, '0')}`);
      } catch {
        noPointR = r.toString(16).padStart(64, '0');
      }
    }
    for (const chain of ['bitcoin', 'ethereum']) {
      const real = victim.find((proof) => proof.CHAIN === chain);
      // b's real proof (its key is recovered, then dropped: it binds b's
      // signing key), then a proof claiming b's address and key for a's card
      // (the payload names a's signing key) with a signature nobody made: r
      // is not the x coordinate of any curve point, so no key recovers.
      const payload = text(real.SIGNED_PAYLOAD).replace(hex(b.identity.edPub), hex(a.identity.edPub));
      expect(payload).toContain(hex(a.identity.edPub));
      const forged = {
        ...real,
        SIGNED_PAYLOAD: hex(new TextEncoder().encode(payload)),
        SIGNATURE: `1b${noPointR}${'00'.repeat(31)}05`,
      };
      last = null;
      verifyChainProof(stale, real);
      expect(verifyChainProof(stale, forged)).toBe(true); // the WASM check alone is fooled
      last = null;
      const contact = contactFromEpm(stale, resign(a, { ...card(a), CHAIN_PROOFS: [real, forged] }));
      expect(contact.addresses[chain === 'bitcoin' ? 'btc' : 'eth']).toBeUndefined();
    }
    // a's own proofs still verify, through the same wallet.
    last = null;
    expect(Object.keys(contactFromEpm(stale, card(a)).addresses).sort()).toEqual(['btc', 'eth', 'sol']);
  });

  it('keeps a contact without an encryption key (it cannot be encrypted to)', () => {
    const a = session(TEST_PHRASE);
    const base = card(a);
    const epm = resign(a, { ...base, KEYS: [base.KEYS[0]] });
    const contact = contactFromEpm(wallet, epm);
    expect(contact.encryptionKey).toBeNull();
  });

  it('keeps a photo only when it is a jpeg/png/webp data URL of at most 64 KiB that inspects', () => {
    const a = session(TEST_PHRASE);
    const withPhoto = (photo) => contactFromEpm(wallet, resign(a, { ...card(a), PHOTO: photo })).photo;
    const goodPng = `data:image/png;base64,${bytesToBase64(png())}`;
    expect(withPhoto(goodPng)).toBe(goodPng);
    expect(withPhoto('https://example.org/photo.jpg')).toBe('');
    expect(withPhoto(`data:image/svg+xml;base64,${bytesToBase64(new TextEncoder().encode('<svg/>'))}`)).toBe('');
    expect(withPhoto(`data:image/jpeg;base64,${bytesToBase64(jpeg(16, 16, 70 * 1024))}`)).toBe('');
    // A PNG labelled as JPEG does not pass the byte inspector's type check.
    expect(withPhoto(`data:image/jpeg;base64,${bytesToBase64(png())}`)).toBe('');
    expect(photoBytesFromDataUrl(goodPng)).toHaveLength(24);
  });

  it('re-importing the same peer ID replaces the stored card', () => {
    const a = session(TEST_PHRASE);
    const first = contactFromEpm(wallet, card(a, { name: 'Ada' }));
    const second = contactFromEpm(wallet, card(a, { name: 'Ada King' }));
    const other = contactFromEpm(wallet, card(session(OTHER_PHRASE), { name: 'Babbage' }));
    let list = upsertContact([], first);
    list = upsertContact(list, other);
    list = upsertContact(list, second);
    expect(list.map((contact) => contact.name)).toEqual(['Ada King', 'Babbage']);
  });

  it('re-checks stored contacts on load', () => {
    const contact = contactFromEpm(wallet, card(session(TEST_PHRASE)));
    expect(sanitizeStoredContact(JSON.parse(JSON.stringify(contact)))).toMatchObject({
      peerId: contact.peerId,
      name: 'Ada Lovelace',
      encryptionKey: contact.encryptionKey,
    });
    expect(sanitizeStoredContact({ peerId: 'x', signingKey: 'zz' })).toBeNull();
    expect(sanitizeStoredContact({ ...contact, photo: 'javascript:alert(1)' }).photo).toBe('');
  });
});
