import { readFile } from 'node:fs/promises';

import { describe, expect, test, vi } from 'vitest';

import {
  ApprovalConfigurationController,
  createApprovalConfiguration,
  renderAccount,
  renderQuarantinedWalletManager,
} from '../origin-app/account.mjs';
import {
  PhotoUrlController,
  inspectPhotoBytes,
} from '../origin-app/photo.mjs';
import { renderSafeInlineTranslation } from '../src/i18n.js';
import { createMessagesPane } from '../src/messages-ui.js';
import { createPeoplePane } from '../src/people-ui.js';
import { createProfilePane } from '../src/profile-ui.js';
import { createAccountShell } from '../src/account-view.js';
import { createTestContext } from './helpers/account-context.mjs';

class SafeNode {
  constructor(tagName, document) {
    this.tagName = tagName;
    this.ownerDocument = document;
    this.children = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.className = '';
    this.disabled = false;
    this.hidden = false;
    this.id = '';
    this.listeners = new Map();
    this.name = '';
    this.style = {};
    this.tabIndex = 0;
    this.type = '';
    this.value = '';
    this._text = '';
    this.classList = {
      add: (...tokens) => this.#setClasses([...this.#classes(), ...tokens]),
      contains: (token) => this.#classes().includes(token),
      remove: (...tokens) => this.#setClasses(this.#classes().filter((token) => !tokens.includes(token))),
      toggle: (token, force) => {
        const present = this.classList.contains(token);
        const enabled = force === undefined ? !present : Boolean(force);
        if (enabled) this.classList.add(token);
        else this.classList.remove(token);
        return enabled;
      },
    };
  }

  #classes() {
    return this.className.split(/\s+/u).filter(Boolean);
  }

  #setClasses(tokens) {
    this.className = [...new Set(tokens.filter(Boolean))].join(' ');
  }

  append(...children) {
    for (const child of children) {
      child.parentNode = this;
      this.children.push(child);
    }
  }

  appendChild(child) {
    this.append(child);
    return child;
  }

  replaceChildren(...children) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this._text = '';
    this.append(...children);
  }

  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter((child) => child !== this);
    this.parentNode = null;
  }

  setAttribute(name, value) {
    if (/^(?:src|srcdoc|style|on)/iu.test(name)) throw new Error(`unsafe attribute ${name}`);
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }

  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type, event = {}) {
    if (!('target' in event)) event.target = this;
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }

  contains(candidate) {
    if (candidate === this) return true;
    return this.children.some((child) => child.contains?.(candidate));
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }

  querySelectorAll(selector) {
    const output = [];
    const selectors = selector.split(',').map((part) => part.trim());
    const matches = (candidate, part) => {
      if (part === '[href]') return typeof candidate.href === 'string' && candidate.href !== '';
      if (part.startsWith('[tabindex]')) return candidate.attributes.has('tabindex');
      const tag = part.match(/^[a-z]+/iu)?.[0]?.toLowerCase();
      if (tag && candidate.tagName !== tag) return false;
      if (part.includes(':checked') && candidate.checked !== true) return false;
      if (part.includes(':not([disabled])') && candidate.disabled) return false;
      const name = part.match(/\[name="([^"]+)"\]/u)?.[1];
      if (name && candidate.name !== name) return false;
      const className = part.match(/\.([a-z0-9_-]+)/iu)?.[1];
      if (className && !candidate.classList.contains(className)) return false;
      return Boolean(tag || name || className);
    };
    const visit = (candidate) => {
      if (selectors.some((part) => matches(candidate, part))) output.push(candidate);
      candidate.children.forEach(visit);
    };
    this.children.forEach(visit);
    return output;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  get isConnected() {
    let current = this;
    while (current?.parentNode) current = current.parentNode;
    return current === this.ownerDocument.body;
  }

  set textContent(value) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this._text = String(value);
  }

  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join('');
  }

  set innerHTML(_value) {
    throw new Error('HTML sink used');
  }

  insertAdjacentHTML() {
    throw new Error('HTML sink used');
  }
}

class SafeDocument {
  constructor() {
    this.body = new SafeNode('body', this);
    this.activeElement = this.body;
  }

  createElement(tagName) {
    return new SafeNode(tagName.toLowerCase(), this);
  }

  createTextNode(value) {
    const node = new SafeNode('#text', this);
    node._text = String(value);
    return node;
  }

  find(predicate) {
    let match = null;
    const visit = (node) => {
      if (!match && predicate(node)) match = node;
      node.children.forEach(visit);
    };
    visit(this.body);
    return match;
  }
}

function modernIdentity(overrides = {}) {
  const descriptor = (purpose, curve, path, signatureProfile, digit) => ({
    bip32Fingerprint: null,
    curve,
    derivation: 'slip10',
    encoding: 'raw',
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keyId: `sha256:${digit.repeat(64)}`,
    path,
    publicKeyHex: digit.repeat(64),
    purpose,
    seedProfile: 'password-scrypt-v2',
    signatureProfile,
  });
  return {
    accountFingerprint: '1234abcd',
    accountIndex: 0,
    accountLabel: null,
    accountPeerId: `16Uiu2H${'1'.repeat(40)}`,
    accountXpub: `xpub${'1'.repeat(107)}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keys: [
      descriptor('asset-review-approval', 'ed25519', "m/44'/0'/0'/2'/0'", 'ed25519-over-sha256-jcs-v1', '2'),
      descriptor('contact-encryption', 'x25519', "m/44'/0'/0'/1'/0'", null, '3'),
      descriptor('sdn-authentication', 'ed25519', "m/44'/0'/0'/0'/0'", 'ed25519-over-sha256-jcs-v1', '4'),
    ],
    schemaVersion: 1,
    seedProfile: 'password-scrypt-v2',
    ...overrides,
  };
}

function control(value) {
  return {
    autocomplete: 'current-password',
    defaultValue: value,
    disabled: false,
    form: null,
    removeAttribute(name) { this[name] = null; },
    setCustomValidity() {},
    setSelectionRange() {},
    value,
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function png(width = 1, height = 1) {
  const bytes = new Uint8Array(24);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  bytes.set([0, 0, 0, 13, 73, 72, 68, 82], 8);
  new DataView(bytes.buffer).setUint32(16, width);
  new DataView(bytes.buffer).setUint32(20, height);
  return bytes;
}

function gif(width = 1, height = 1) {
  const bytes = new Uint8Array(10);
  bytes.set(new TextEncoder().encode('GIF89a'));
  new DataView(bytes.buffer).setUint16(6, width, true);
  new DataView(bytes.buffer).setUint16(8, height, true);
  return bytes;
}

function webp(width = 1, height = 1) {
  const bytes = new Uint8Array(30);
  bytes.set(new TextEncoder().encode('RIFF'), 0);
  bytes.set(new TextEncoder().encode('WEBPVP8X'), 8);
  const widthMinusOne = width - 1;
  const heightMinusOne = height - 1;
  bytes[24] = widthMinusOne & 255;
  bytes[25] = (widthMinusOne >>> 8) & 255;
  bytes[26] = (widthMinusOne >>> 16) & 255;
  bytes[27] = heightMinusOne & 255;
  bytes[28] = (heightMinusOne >>> 8) & 255;
  bytes[29] = (heightMinusOne >>> 16) & 255;
  return bytes;
}

function jpeg(width = 1, height = 1) {
  return Uint8Array.from([
    0xff, 0xd8,
    0xff, 0xc0, 0x00, 0x11, 0x08,
    (height >>> 8) & 255, height & 255,
    (width >>> 8) & 255, width & 255,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    0xff, 0xd9,
  ]);
}

describe('safe wallet-origin rendering', () => {
  test('renders origin Account quarantine metadata and exact actions without exposing raw storage', () => {
    const document = new SafeDocument();
    const container = document.createElement('section');
    document.body.append(container);
    const key = '</code><img src=x onerror=alert(1)>';
    const rawAttack = '<svg onload=alert(1)>raw-secret</svg>';
    const rendered = renderQuarantinedWalletManager(container, [{
      exportable: true,
      key,
      oversized: false,
      raw: rawAttack,
      rawLength: 42,
    }, {
      exportable: false,
      key: 'hd-wallet.remembered.v2.pending',
      oversized: true,
      rawLength: 2_000_000,
    }], { document });

    expect(container.textContent).toContain(key);
    expect(container.textContent).not.toContain(rawAttack);
    expect(document.find((node) => node.tagName === 'img')).toBeNull();
    expect(document.find((node) => node.tagName === 'svg')).toBeNull();
    expect(rendered.rows[0].exportButton.dataset).toMatchObject({
      walletAction: 'export-quarantined-wallet',
      walletQuarantineKey: key,
    });
    expect(rendered.rows[0].deleteButton.dataset).toMatchObject({
      walletAction: 'delete-quarantined-wallet',
      walletQuarantineKey: key,
    });
    expect(rendered.rows[0].confirmation.dataset.walletQuarantineConfirmation).toBe(key);
    expect(rendered.rows[1].exportButton.textContent).toBe('Export unavailable');
    expect(container.textContent).toContain('Export unavailable (2000000 characters)');
  });

  test('allows only exact nested strong/code translation tokens and renders attacks as text', () => {
    const document = new SafeDocument();
    const target = document.createElement('p');
    expect(renderSafeInlineTranslation(target, 'Use <strong>one <code>safe</code> phrase</strong>.', document)).toBe(true);
    expect(target.children.map((child) => child.tagName)).toContain('strong');
    expect(target.textContent).toBe('Use one safe phrase.');

    for (const attack of [
      '<img src=x onerror=alert(1)>',
      '<strong class=x>unsafe</strong>',
      '<strong><code>bad</strong></code>',
      '<svg><script>alert(1)</script></svg>',
    ]) {
      expect(renderSafeInlineTranslation(target, attack, document)).toBe(false);
      expect(target.children).toHaveLength(1);
      expect(target.children[0].tagName).toBe('#text');
      expect(target.textContent).toBe(attack);
    }
  });
});

describe('approval configuration double-entry', () => {
  test('derives two fresh rounds, reuses only the immutable DTO, and makes clear terminal', async () => {
    const destroyed = [];
    const seen = [];
    const wasm = {
      async derivePasswordIdentity(input) {
        seen.push(input);
        return { handle: Object.freeze({ round: seen.length }), identity: modernIdentity({ accountLabel: null }) };
      },
      destroySdnIdentity(handle) { destroyed.push(handle); },
    };
    let rounds = 0;
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => {
        rounds += 1;
        return {
          passwordControl: control('correct horse battery staple'),
          usernameControl: control('alice'),
        };
      },
      wasm,
    });
    const first = await controller.confirm();
    expect(first).toEqual(createApprovalConfiguration(modernIdentity({ accountLabel: null })));
    expect(Object.isFrozen(first)).toBe(true);
    expect(rounds).toBe(2);
    expect(destroyed).toHaveLength(2);
    expect(seen[0].usernameUtf8).not.toBe(seen[1].usernameUtf8);
    expect(seen[0].passwordUtf8).not.toBe(seen[1].passwordUtf8);
    expect(Array.from(seen[0].passwordUtf8)).toEqual(Array(seen[0].passwordUtf8.length).fill(0));
    expect(await controller.confirm()).toBe(first);
    expect(rounds).toBe(2);
    controller.clear();
    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toBe(2);
  });

  test.each([
    ['identity scheme', { identityScheme: 'sdn-bip32-slip10-purpose-v2' }],
    ['seed profile', { seedProfile: 'password-scrypt-v3' }],
    ['account xpub', { accountXpub: `xpub${'9'.repeat(107)}` }],
    ['approval path', { approval: { path: "m/44'/0'/0'/9'/0'" } }],
    ['approval key', { approval: { publicKeyHex: '9'.repeat(64) } }],
    ['approval key ID', { approval: { keyId: `sha256:${'9'.repeat(64)}` } }],
    ['contact key', { keyIndex: 1, key: { publicKeyHex: '9'.repeat(64) } }],
    ['authentication descriptor', { keyIndex: 2, key: { path: "m/44'/0'/0'/8'/0'" } }],
  ])('returns one generic error and no DTO for a %s mismatch', async (_label, mutation) => {
    const destroyed = [];
    const baseline = modernIdentity({ accountLabel: null });
    const changed = structuredClone(baseline);
    if (mutation.approval) Object.assign(changed.keys[0], mutation.approval);
    else if (mutation.key) Object.assign(changed.keys[mutation.keyIndex], mutation.key);
    else Object.assign(changed, mutation);
    let call = 0;
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => ({
        passwordControl: control(call === 0 ? 'correct horse battery staple' : 'different password value'),
        usernameControl: control(call === 0 ? 'alice' : 'mallory'),
      }),
      wasm: {
        async derivePasswordIdentity() {
          const identity = call === 0 ? baseline : changed;
          call += 1;
          return { handle: { call }, identity };
        },
        destroySdnIdentity(handle) { destroyed.push(handle); },
      },
    });
    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
      message: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(destroyed).toHaveLength(2);
    expect(controller.confirmed).toBeNull();
  });

  test('destroys a returned handle when the native identity is malformed', async () => {
    const destroyed = [];
    const seen = [];
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => ({
        passwordControl: control('correct horse battery staple'),
        usernameControl: control('alice'),
      }),
      wasm: {
        async derivePasswordIdentity(input) {
          seen.push(input);
          return { handle: 'malformed-handle', identity: { schemaVersion: 1 } };
        },
        destroySdnIdentity(handle) { destroyed.push(handle); },
      },
    });
    await expect(controller.confirm()).rejects.toMatchObject({ code: 'CREDENTIAL_CONFIRMATION_MISMATCH' });
    expect(destroyed).toEqual(['malformed-handle']);
    expect(Array.from(seen[0].passwordUtf8)).toEqual(Array(seen[0].passwordUtf8.length).fill(0));
  });

  test('retains ownership and retries cleanup when native destruction initially fails', async () => {
    const handle = Object.freeze({ round: 1 });
    let derives = 0;
    let destroyCalls = 0;
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => ({
        passwordControl: control('correct horse battery staple'),
        usernameControl: control('alice'),
      }),
      wasm: {
        async derivePasswordIdentity() {
          derives += 1;
          return { handle, identity: modernIdentity() };
        },
        destroySdnIdentity(candidate) {
          expect(candidate).toBe(handle);
          destroyCalls += 1;
          if (destroyCalls === 1) throw new Error('native destruction failed');
        },
      },
    });
    await expect(controller.confirm()).rejects.toMatchObject({ code: 'CREDENTIAL_CONFIRMATION_MISMATCH' });
    expect(derives).toBe(1);
    expect(destroyCalls).toBe(2);
    expect(controller.confirmed).toBeNull();
    controller.clear();
    expect(destroyCalls).toBe(2);
  });

  test('retains a malformed-result handle until a later cleanup succeeds', async () => {
    let destroyCalls = 0;
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => ({
        passwordControl: control('correct horse battery staple'),
        usernameControl: control('alice'),
      }),
      wasm: {
        async derivePasswordIdentity() {
          return { handle: 'malformed-owned-handle', identity: { schemaVersion: 1 } };
        },
        destroySdnIdentity(handle) {
          expect(handle).toBe('malformed-owned-handle');
          destroyCalls += 1;
          if (destroyCalls === 1) throw new Error('cleanup failed once');
        },
      },
    });
    await expect(controller.confirm()).rejects.toMatchObject({ code: 'CREDENTIAL_CONFIRMATION_MISMATCH' });
    expect(destroyCalls).toBe(1);
    expect(controller.confirmed).toBeNull();
    controller.clear();
    expect(destroyCalls).toBe(2);
  });

  test('rejects two matching entries when they do not reproduce the displayed Account', async () => {
    const displayed = modernIdentity();
    const different = modernIdentity({ accountXpub: `xpub${'9'.repeat(107)}` });
    const destroyed = [];
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => ({
        passwordControl: control('correct horse battery staple'),
        usernameControl: control('alice'),
      }),
      expectedIdentity: displayed,
      wasm: {
        async derivePasswordIdentity() {
          return { handle: { round: destroyed.length }, identity: different };
        },
        destroySdnIdentity(handle) { destroyed.push(handle); },
      },
    });
    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
      message: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(destroyed).toHaveLength(2);
    expect(controller.confirmed).toBeNull();
  });

  test('never builds approval material for a legacy identity', () => {
    expect(() => createApprovalConfiguration(modernIdentity({
      identityScheme: 'sdn-fast-password-auth-v1-legacy',
      keys: [],
      seedProfile: 'password-fast-v1-legacy',
    }))).toThrow(/Approval unavailable — migrate to the new wallet profile/u);
  });
});

describe('local byte-only photos', () => {
  test.each([
    ['PNG', png()],
    ['JPEG', jpeg()],
    ['WebP', webp()],
    ['GIF', gif()],
  ])('accepts decoded size-bounded %s fixture bytes', (_name, bytes) => {
    expect(inspectPhotoBytes(bytes)).toMatchObject({ height: 1, width: 1 });
  });

  test.each([
    ['invalid magic', new Uint8Array([1, 2, 3, 4])],
    ['oversize', new Uint8Array((2 * 1024 * 1024) + 1)],
    ['oversize dimensions', png(2049, 1)],
    ['SVG', new TextEncoder().encode('<svg onload=alert(1)>')],
    ['HTML', new TextEncoder().encode('<img src=https://attacker.invalid>')],
    ['data URL', 'data:image/png;base64,AAAA'],
    ['remote URL', 'https://attacker.invalid/photo.png'],
    ['unknown scheme', 'javascript:alert(1)'],
  ])('rejects %s before URL creation', (_name, value) => {
    expect(() => inspectPhotoBytes(value)).toThrow();
  });

  test('revokes every blob URL on replacement, image error, logout, and destroy', async () => {
    const revoked = [];
    let next = 0;
    const urls = {
      createObjectURL: () => `blob:wallet-${++next}`,
      revokeObjectURL: (value) => revoked.push(value),
    };
    const photos = new PhotoUrlController({
      Blob,
      decode: async (_blob, expected) => expected,
      URL: urls,
    });
    expect(await photos.replace(png())).toBe('blob:wallet-1');
    expect(await photos.replace(gif())).toBe('blob:wallet-2');
    expect(revoked).toEqual(['blob:wallet-1']);
    photos.imageError('blob:wallet-2');
    expect(revoked).toEqual(['blob:wallet-1', 'blob:wallet-2']);
    expect(await photos.replace(webp())).toBe('blob:wallet-3');
    photos.logout();
    expect(await photos.replace(jpeg())).toBe('blob:wallet-4');
    photos.destroy();
    expect(revoked).toEqual(['blob:wallet-1', 'blob:wallet-2', 'blob:wallet-3', 'blob:wallet-4']);
  });

  test('an older out-of-order decode cannot replace or revoke the newest photo', async () => {
    const decodes = [];
    const revoked = [];
    let created = 0;
    const photos = new PhotoUrlController({
      Blob,
      decode: (_blob, expected) => {
        const pending = deferred();
        decodes.push({ expected, pending });
        return pending.promise;
      },
      URL: {
        createObjectURL: () => `blob:race-${++created}`,
        revokeObjectURL: (value) => revoked.push(value),
      },
    });
    const older = photos.replace(png());
    const newer = photos.replace(gif());
    decodes[1].pending.resolve(decodes[1].expected);
    await expect(newer).resolves.toBe('blob:race-1');
    decodes[0].pending.resolve(decodes[0].expected);
    await expect(older).rejects.toMatchObject({ code: 'PHOTO_REPLACED' });
    expect(created).toBe(1);
    expect(revoked).toEqual([]);
    photos.destroy();
    expect(revoked).toEqual(['blob:race-1']);
  });

  test.each(['logout', 'destroy'])('%s during decode prevents later URL creation', async (method) => {
    const pending = deferred();
    let created = 0;
    const photos = new PhotoUrlController({
      Blob,
      decode: () => pending.promise,
      URL: {
        createObjectURL: () => `blob:late-${++created}`,
        revokeObjectURL() {},
      },
    });
    const replacement = photos.replace(webp());
    photos[method]();
    pending.resolve({ height: 1, width: 1 });
    await expect(replacement).rejects.toMatchObject({ code: 'PHOTO_REPLACED' });
    expect(created).toBe(0);
  });
});

const HOSTILE = '<img src=x onerror=alert(1)><script>bad()</script><b>bold</b>';

function elementsNamed(document, names) {
  const found = [];
  const visit = (node) => {
    if (names.includes(node.tagName)) found.push(node);
    node.children.forEach(visit);
  };
  visit(document.body);
  return found;
}

async function settle(check) {
  for (let index = 0; index < 200; index += 1) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

describe('account view renders hostile text only as text', () => {
  test('profile fields and the name become text, never markup', () => {
    const document = new SafeDocument();
    const panel = document.createElement('section');
    document.body.append(panel);
    const ctx = createTestContext({
      document,
      kind: 'seed',
      profile: { name: HOSTILE, jobTitle: HOSTILE, organization: HOSTILE, city: HOSTILE },
    });
    ctx.session = () => ({ kind: 'seed', account: 0, identity: { edPub: new Uint8Array(32), xPub: new Uint8Array(32), peerId: '12D3KooWtest', account: 0 } });
    createProfilePane(panel, ctx).show();
    expect(elementsNamed(document, ['img', 'script', 'b'])).toEqual([]);
    expect(panel.textContent).toContain(HOSTILE);
  });

  test('a contact name, photo and addresses become text, never markup', () => {
    const document = new SafeDocument();
    const panel = document.createElement('section');
    document.body.append(panel);
    const ctx = createTestContext({
      document,
      contacts: [{
        peerId: '12D3KooWJB7pwCc5pMGNVykovHTSMHGTxiQBEFBVwsgFoAmMkmWZ',
        name: HOSTILE,
        encryptionKey: 'ab'.repeat(32),
        signingKey: 'cd'.repeat(32),
        photo: 'javascript:alert(1)',
        addresses: { eth: HOSTILE },
      }],
    });
    createPeoplePane(panel, ctx).show();
    expect(elementsNamed(document, ['img', 'script', 'b'])).toEqual([]);
    expect(panel.textContent).toContain(HOSTILE);
  });

  test('FILE_NAME, NAME, MEDIA_TYPE and decrypted text become text, never markup', async () => {
    const document = new SafeDocument();
    const panel = document.createElement('section');
    document.body.append(panel);
    const envelopes = {
      verifyInput: () => ({
        kind: 'rec',
        valid: true,
        reason: null,
        timestampValid: true,
        signer: { peerId: '12D3KooWtest' },
        notice: { PUBLISH_TIMESTAMP: '2026-10-15T00:00:00.000Z', FILE_NAME: HOSTILE },
        content: new TextEncoder().encode(HOSTILE),
        fileName: HOSTILE,
        size: 3,
      }),
      decryptFile: () => ({
        ok: true,
        isFileRecord: true,
        file: { name: HOSTILE, mediaType: `text/plain; x=${HOSTILE}`, size: 3, content: new TextEncoder().encode(HOSTILE) },
        signature: null,
      }),
    };
    const ctx = createTestContext({ document, envelopes, profile: { name: HOSTILE } });
    ctx.session = () => ({ kind: 'seed', account: 0, identity: { edPub: new Uint8Array(32), xPub: new Uint8Array(32), peerId: '12D3KooWself', account: 0 } });
    ctx.keys.withXKey = (fn) => fn(new Uint8Array(32));
    const pane = createMessagesPane(panel, ctx);
    pane.show({ mode: 'verify' });
    const file = { name: 'x.rec', size: 3, type: '', arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer };
    const zone = document.find((node) => node.classList.contains('drop-zone'));
    zone.dispatch('drop', { dataTransfer: { files: [file] } });
    await settle(() => panel.textContent.includes('Valid signature'));
    expect(panel.textContent).toContain('Valid signature');
    expect(elementsNamed(document, ['img', 'script', 'b'])).toEqual([]);

    pane.reset();
    pane.show({ mode: 'decrypt' });
    const decryptZone = document.find((node) => node.classList.contains('drop-zone'));
    decryptZone.dispatch('drop', { dataTransfer: { files: [file] } });
    await settle(() => panel.textContent.includes('Decrypted'));
    expect(panel.textContent).toContain('Decrypted');
    expect(panel.textContent).toContain(HOSTILE);
    expect(elementsNamed(document, ['img', 'script', 'b'])).toEqual([]);
  });

  test('the identity bar shows a hostile name as text', () => {
    const document = new SafeDocument();
    const root = document.createElement('div');
    const ids = ['account-close', 'account-name', 'account-add-name', 'account-peer-id', 'account-copy-peer', 'account-status', 'account-avatar'];
    const byId = new Map();
    for (const id of ids) {
      const node = document.createElement(id === 'account-close' || id.includes('copy') || id.includes('add') ? 'button' : 'span');
      node.id = id;
      byId.set(`#${id}`, node);
      root.append(node);
    }
    for (const section of ['profile', 'messages', 'people', 'assets', 'settings']) {
      const tab = document.createElement('button');
      tab.id = `account-tab-${section}`;
      const panel = document.createElement('section');
      panel.id = `account-pane-${section}`;
      byId.set(`#${tab.id}`, tab);
      byId.set(`#${panel.id}`, panel);
      root.append(tab, panel);
    }
    root.querySelector = (selector) => byId.get(selector) ?? null;
    document.body.append(root);
    const win = { location: { hash: '', pathname: '/', search: '' }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} };
    const shell = createAccountShell({ document, window: win, root, storage: null });
    shell.setIdentity({ name: HOSTILE, avatar: { initials: 'X' }, peerId: HOSTILE, statusText: HOSTILE });
    expect(elementsNamed(document, ['img', 'script', 'b'])).toEqual([]);
    expect(byId.get('#account-name').textContent).toBe(HOSTILE);
  });
});

test('Task 9 sources contain no HTML sinks, Math.random, or remote photo path', async () => {
  const paths = [
    '../origin-app/controller.mjs',
    '../origin-app/operations.mjs',
    '../origin-app/app.mjs',
    '../origin-app/account.mjs',
    '../origin-app/photo.mjs',
    '../origin-app/relay.mjs',
    '../src/app.js',
    '../src/template.js',
    '../src/i18n.js',
    '../src/seed-slots.js',
    '../src/account-view.js',
    '../src/account-storage.js',
    '../src/identity-keys.js',
    '../src/contact-card.js',
    '../src/ui-dom.js',
    '../src/profile-ui.js',
    '../src/messages-ui.js',
    '../src/people-ui.js',
    '../src/assets-ui.js',
    '../src/settings-ui.js',
    '../src/balances.js',
    '../src/envelopes.js',
    '../account/index.mjs',
  ];
  // Every markup sink, not only innerHTML. app.js parses one string with
  // DOMParser: the constant template (appendTrustedStaticTemplate), checked below.
  const SINKS = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe|DOMParser/u;
  for (const path of paths) {
    let source = await readFile(new URL(path, import.meta.url), 'utf8');
    expect(source, path).not.toMatch(/Math\.random|https?:\/\/[^\s'"]*(?:avatar|photo)/iu);
    if (path === '../src/app.js') {
      const parserUses = source.match(/DOMParser/gu) ?? [];
      expect(parserUses, 'app.js parses only the static template').toHaveLength(1);
      expect(source).toMatch(/function appendTrustedStaticTemplate\(container, source\) \{\n  const parser = new DOMParser\(\);/u);
      expect(source.match(/appendTrustedStaticTemplate\(/gu)).toHaveLength(2);
      expect(source).toMatch(/appendTrustedStaticTemplate\(container, getModalHTML\(\)\)/u);
      source = source.replace('new DOMParser()', '');
    }
    expect(source, path).not.toMatch(SINKS);
  }
  // The template is one constant string: no ${} interpolation.
  const template = await readFile(new URL('../src/template.js', import.meta.url), 'utf8');
  expect(template).not.toMatch(/\$\{/u);
  const legacyApp = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  expect(legacyApp).not.toMatch(/readAsDataURL|state\.vcardPhoto(?!Bytes|Url)|VALUE=URI:data:image/u);
});
