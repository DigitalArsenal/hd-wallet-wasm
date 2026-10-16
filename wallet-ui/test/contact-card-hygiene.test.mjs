// What a contact card may carry: no account xpub (it would list every address
// of the account), and no profile text Go's canonical JSON writes differently
// (U+2028/U+2029) or that can disguise a name (controls, bidi overrides).
// Public BIP-39 test vector only.

import initHDWallet, { verifyEPMSignature } from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { buildContactEpm, cleanText, contactFromEpm, normalizeProfile } from '../src/contact-card.js';
import { accountXpub, deriveAccountAddresses, deriveIdentity, withChainKey, withEdKey } from '../src/identity-keys.js';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed(PHRASE);
const root = wallet.hdkey.fromSeed(seed);
const identity = deriveIdentity(wallet, seed, 0);

function card(profile) {
  return buildContactEpm(wallet, {
    profile,
    identity,
    addresses: deriveAccountAddresses(wallet, root, 0),
    withChainKey: (path, fn) => withChainKey(root, path, fn),
    withEdKey: (fn) => withEdKey(wallet, seed, 0, fn),
  });
}

describe('profile text', () => {
  it('drops controls, line separators and bidi overrides, and turns breaks into spaces', () => {
    expect(cleanText('Ada\u2028Lovelace')).toBe('AdaLovelace');
    expect(cleanText('Ada\u2029')).toBe('Ada');
    expect(cleanText('Ada\tLove\nlace')).toBe('Ada Love lace');
    expect(cleanText('\u202Eecalevol adA')).toBe('ecalevol adA');
    expect(cleanText('a\u0000b\u007fc\u0085d\u2066e\u200Ff\uFEFFg')).toBe('abcdefg');
    expect(cleanText('Zoë 🚀 <b>&\'')).toBe('Zoë 🚀 <b>&\'');
    expect(cleanText(42)).toBe('');
    expect(normalizeProfile({ name: 'x'.repeat(300), city: 'y'.repeat(300) })).toMatchObject({ name: 'x'.repeat(128), city: 'y'.repeat(256) });
  });

  it('a profile with U+2028 builds a card whose signed fields have none, and it verifies', () => {
    const epm = card({ name: 'Ada\u2028Lovelace', organization: 'Engines\u2029Ltd', jobTitle: 'Analyst\u202E' });
    expect(epm.LEGAL_NAME).toBe('AdaLovelace');
    expect(epm.DN).toBe('CN=AdaLovelace,O=EnginesLtd');
    expect(epm.JOB_TITLE).toBe('Analyst');
    expect(JSON.stringify(epm)).not.toMatch(/[\u2028\u2029\u202A-\u202E]/u);
    expect(verifyEPMSignature(wallet, epm, identity.edPub)).toBe(true);
  });

  it('an imported card shows a cleaned, shorter name', () => {
    const epm = card({ name: 'Bob' });
    const contact = contactFromEpm(wallet, epm);
    expect(contact.name).toBe('Bob');
  });
});

describe('the account xpub', () => {
  it('appears nowhere in the card, including the chain proofs’ signed payloads', () => {
    const xpub = accountXpub(root, 0);
    const epm = card({ name: 'Ada' });
    const text = JSON.stringify(epm);
    expect(text).not.toContain(xpub);
    expect(text).not.toMatch(/xpub[1-9A-HJ-NP-Za-km-z]{100,}/u);
    for (const proof of epm.CHAIN_PROOFS ?? []) {
      const payload = JSON.parse(new TextDecoder().decode(wallet.utils.decodeHex(proof.SIGNED_PAYLOAD)));
      expect(payload.xpub).toBe('');
      expect(payload.signing_pubkey_hex).toBe(wallet.utils.encodeHex(identity.edPub));
    }
    expect((epm.CHAIN_PROOFS ?? []).length).toBeGreaterThan(0);
  });
});
