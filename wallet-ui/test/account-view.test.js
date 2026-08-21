// The standalone account view is a PUBLIC export. These tests pin the promises
// a consumer is entitled to rely on, because the whole reason this module
// exists is that the account screen used to be reachable only by calling
// internals — and an export that drifts is no better than an internal.
//
// The DOM here is a hand-rolled stub, matching test/dom-security.test.mjs. This
// package ships no DOM test environment on purpose, and adding jsdom for one
// component would put a dependency into a lockfile that a signed release
// verifies byte for byte. The component only needs the handful of DOM calls
// stubbed below, and a stub proves it uses no more than that.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_ACCOUNT_TABS,
  createAccountView,
  mountAccountView,
} from '../account/index.mjs';

const ROOT = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

// ---- minimal DOM ----------------------------------------------------------

class StubNode {
  constructor(tagName, ownerDocument) {
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.className = '';
    this.id = '';
    this.hidden = false;
    this.disabled = false;
    this.type = '';
    this.title = '';
    this.value = '';
    this.alt = '';
    this.accept = '';
    this.placeholder = '';
    this.autoplay = false;
    this.playsInline = false;
    this.srcObject = null;
    this.videoWidth = 0;
    this.videoHeight = 0;
    this.width = 0;
    this.height = 0;
    this._text = '';
    this.classList = {
      add: (...tokens) => this.#setClasses([...this.#classes(), ...tokens]),
      contains: (token) => this.#classes().includes(token),
      remove: (...tokens) => this.#setClasses(this.#classes().filter((c) => !tokens.includes(c))),
      toggle: (token, force) => {
        const on = force === undefined ? !this.#classes().includes(token) : Boolean(force);
        if (on) this.classList.add(token);
        else this.classList.remove(token);
        return on;
      },
    };
  }

  #classes() {
    return this.className.split(' ').filter(Boolean);
  }

  #setClasses(tokens) {
    this.className = [...new Set(tokens)].join(' ');
  }

  get textContent() {
    if (this.childNodes.length === 0) return this._text;
    return this.childNodes.map((c) => c.textContent).join('');
  }

  set textContent(value) {
    this.childNodes = [];
    this._text = value === undefined || value === null ? '' : String(value);
  }

  append(...nodes) {
    for (const node of nodes) {
      if (node === null || node === undefined) continue;
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }

  insertBefore(node, reference) {
    const index = this.childNodes.indexOf(reference);
    node.parentNode = this;
    if (index < 0) this.childNodes.push(node);
    else this.childNodes.splice(index, 0, node);
  }

  replaceChildren(...nodes) {
    this.childNodes = [];
    this._text = '';
    this.append(...nodes);
  }

  remove() {
    if (!this.parentNode) return;
    const index = this.parentNode.childNodes.indexOf(this);
    if (index >= 0) this.parentNode.childNodes.splice(index, 1);
    this.parentNode = null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  dispatch(type) {
    for (const handler of this.listeners.get(type) ?? []) handler({ type, target: this });
  }

  click() {
    this.dispatch('click');
  }

  descendants() {
    const out = [];
    for (const child of this.childNodes) {
      out.push(child, ...child.descendants());
    }
    return out;
  }

  // A tiny selector engine: ".class", "#id", "tag", "[attr=value]", and
  // whitespace-free conjunctions of those. Enough to assert structure without
  // pretending to be a browser.
  matches(selector) {
    const parts = selector.match(/(\.[^.#[\]]+|#[^.#[\]]+|\[[^\]]+\]|^[a-z]+)/gu) ?? [];
    return parts.every((part) => {
      if (part.startsWith('.')) return this.classList.contains(part.slice(1));
      if (part.startsWith('#')) return this.id === part.slice(1);
      if (part.startsWith('[')) {
        const [name, raw] = part.slice(1, -1).split('=');
        if (raw === undefined) return this.getAttribute(name) !== null;
        const want = raw.replace(/^["']|["']$/gu, '');
        if (name.startsWith('data-')) {
          const key = name.slice(5).replace(/-([a-z])/gu, (_, c) => c.toUpperCase());
          return this.dataset[key] === want;
        }
        return this.getAttribute(name) === want;
      }
      return this.tagName === part.toUpperCase();
    });
  }

  querySelectorAll(selector) {
    return this.descendants().filter((node) => node.matches(selector));
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
}

function stubDocument() {
  const doc = {
    defaultView: { navigator: {} },
    createElement(tagName) {
      return new StubNode(tagName, doc);
    },
    createTextNode(text) {
      const node = new StubNode('#text', doc);
      node.textContent = text;
      return node;
    },
  };
  doc.body = new StubNode('body', doc);
  return doc;
}

const flush = async () => {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
};

// ---- behaviour ------------------------------------------------------------

describe('account view export', () => {
  it('mounts without a driven transaction — the reason this export exists', () => {
    const doc = stubDocument();
    const view = mountAccountView(doc.body, { document: doc, title: 'Ada' });
    expect(doc.body.querySelector('[data-wallet-account-view]')).not.toBeNull();
    expect(view.element.querySelector('.account-header-name').textContent).toBe('Ada');
  });

  it('keeps the wallet app tab grammar so one stylesheet dresses both', () => {
    const doc = stubDocument();
    const view = createAccountView({ document: doc });
    expect(view.element.querySelector('.modal-tabs')).not.toBeNull();
    expect(view.element.querySelectorAll('.modal-tab')).toHaveLength(DEFAULT_ACCOUNT_TABS.length);
    for (const tab of DEFAULT_ACCOUNT_TABS) {
      const control = view.element.querySelector(`[data-modal-tab=${tab.id}-tab-content]`);
      expect(control, `tab ${tab.id}`).not.toBeNull();
      expect(control.textContent).toBe(tab.label);
      expect(view.element.querySelector(`#${tab.id}-tab-content`)).not.toBeNull();
    }
  });

  it('ships the same tab labels the wallet app itself renders', () => {
    const template = read('src/template.js');
    for (const tab of DEFAULT_ACCOUNT_TABS) {
      expect(template, `tab ${tab.label}`).toContain(`>${tab.label}<`);
    }
  });

  it('puts the bond value at the top, in the header', () => {
    const doc = stubDocument();
    const view = createAccountView({ document: doc, bond: { value: '$1,204.55' } });
    const header = view.element.querySelector('.account-modal-header');
    expect(header.querySelector('#wallet-bond-value').textContent).toBe('$1,204.55');
    expect(header.querySelector('.ph-portfolio-label').textContent).toBe('Bond');
  });

  it('lets a consumer add its own tab instead of forking the strip', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      tabs: [
        ...DEFAULT_ACCOUNT_TABS.slice(0, 4),
        { id: 'node', label: 'Node', render: (panel) => panel.append(doc.createTextNode('peer facts')) },
        DEFAULT_ACCOUNT_TABS[4],
      ],
    });
    expect(view.element.querySelectorAll('.modal-tab')).toHaveLength(6);
    expect(view.panel('node').textContent).toBe('peer facts');
  });

  it('activates exactly one tab at a time', () => {
    const doc = stubDocument();
    const view = createAccountView({ document: doc });
    expect(view.getActiveTab()).toBe('identity');
    view.setActiveTab('wallet');
    expect(view.getActiveTab()).toBe('wallet');
    expect(view.element.querySelectorAll('.modal-tab.active')).toHaveLength(1);
    expect(view.element.querySelectorAll('.modal-tab-content.active')).toHaveLength(1);
    expect(view.element.querySelector('#wallet-tab-content').classList.contains('active')).toBe(true);
  });

  it('clicking a tab switches it', () => {
    const doc = stubDocument();
    const view = createAccountView({ document: doc });
    view.element.querySelector('[data-modal-tab=manage-tab-content]').click();
    expect(view.getActiveTab()).toBe('manage');
  });

  it('renders editable vCard fields and hands their values back on save', async () => {
    const doc = stubDocument();
    let saved = null;
    const view = createAccountView({
      document: doc,
      identity: {
        fields: [
          { id: 'name', label: 'Name', value: 'Ada' },
          { id: 'organization', label: 'Organization', value: '' },
        ],
        onSave: (values) => { saved = values; },
      },
    });
    view.element.querySelector('#identity-field-organization').value = 'Analytical Engines';
    view.element.querySelector('.identity-save-row').querySelector('.glass-btn').click();
    await flush();
    expect(saved).toEqual({ name: 'Ada', organization: 'Analytical Engines' });
    expect(view.element.querySelector('.identity-save-status').textContent).toBe('Saved');
  });

  it('reports a refused save instead of claiming success', async () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      identity: {
        fields: [{ id: 'name', label: 'Name', value: 'Ada' }],
        onSave: () => { throw new Error('this entry comes from the node config file'); },
      },
    });
    view.element.querySelector('.identity-save-row').querySelector('.glass-btn').click();
    await flush();
    expect(view.element.querySelector('.identity-save-status').textContent)
      .toBe('this entry comes from the node config file');
  });

  it('renders a read-only field as a value, never as a disabled input', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      identity: { fields: [{ id: 'fingerprint', label: 'Fingerprint', value: '9f2c1a7b', readOnly: true }] },
    });
    expect(view.element.querySelector('#identity-field-fingerprint')).toBeNull();
    expect(view.element.querySelector('.identity-field-value').textContent).toBe('9f2c1a7b');
    expect(view.element.descendants().filter((n) => n.disabled)).toHaveLength(0);
  });

  it('hides the save control when nothing on the tab is editable', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      identity: { fields: [{ id: 'fingerprint', label: 'Fingerprint', value: 'x', readOnly: true }] },
    });
    expect(view.element.querySelector('.identity-save-row').hidden).toBe(true);
  });

  it('offers the wallet app photo controls and reports storage failure honestly', async () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      identity: { onPhoto: () => { throw new Error('the node could not store the image'); } },
    });
    const actions = view.element.querySelector('.photo-actions');
    const labels = actions.querySelectorAll('.glass-btn').map((b) => b.textContent);
    expect(labels).toEqual(['Upload', 'Use Camera', 'Capture', 'Cancel', 'Remove']);

    const fileInput = view.element.querySelector('.photo-file-input');
    fileInput.files = [{ type: 'image/png' }];
    fileInput.dispatch('change');
    await flush();
    expect(view.element.querySelector('.photo-status').textContent)
      .toBe('the node could not store the image');
  });

  it('says so when the browser has no camera rather than failing silently', async () => {
    const doc = stubDocument();
    const view = createAccountView({ document: doc, identity: {} });
    view.element.querySelector('.photo-actions').querySelectorAll('.glass-btn')[1].click();
    await flush();
    expect(view.element.querySelector('.photo-status').textContent)
      .toBe('This browser has no camera available.');
  });

  it('shows the photo from whatever origin the consumer serves it from', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      identity: { photoUrl: '/ipfs/bafkreiprofilephoto' },
    });
    const image = view.element.querySelector('.photo-image');
    expect(image.hidden).toBe(false);
    expect(image.src).toBe('/ipfs/bafkreiprofilephoto');
  });

  it('escapes caller text rather than parsing it as markup', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      title: '<img src=x onerror=alert(1)>',
      chips: [{ label: '<script>bad()</script>' }],
    });
    // The only <img> in the view is the photo element this component creates.
    // Caller text never becomes an element.
    expect(view.element.querySelectorAll('img')).toHaveLength(1);
    expect(view.element.querySelector('script')).toBeNull();
    expect(view.element.querySelector('.account-header-name').textContent)
      .toBe('<img src=x onerror=alert(1)>');
    expect(view.element.querySelector('.account-chip').textContent).toBe('<script>bad()</script>');
  });

  it('updates in place without stomping fields the caller did not send', () => {
    const doc = stubDocument();
    const view = createAccountView({
      document: doc,
      title: 'Ada',
      bond: { value: '$1.00' },
      identity: { fields: [{ id: 'name', label: 'Name', value: 'Ada' }] },
    });
    view.update({ bond: { value: '$2.00' } });
    expect(view.element.querySelector('#wallet-bond-value').textContent).toBe('$2.00');
    expect(view.element.querySelector('.account-header-name').textContent).toBe('Ada');
    expect(view.element.querySelector('#identity-field-name').value).toBe('Ada');
  });

  it('destroy removes the view from the page', () => {
    const doc = stubDocument();
    const view = mountAccountView(doc.body, { document: doc });
    view.destroy();
    expect(doc.body.querySelector('[data-wallet-account-view]')).toBeNull();
  });
});

// ---- boundaries -----------------------------------------------------------

describe('account view boundaries', () => {
  it('never uses innerHTML', () => {
    const source = read('account/index.mjs');
    expect(source).not.toContain('innerHTML');
    expect(source).not.toContain('outerHTML');
    expect(source).not.toContain('insertAdjacentHTML');
  });

  it('carries no wallet core, no WASM and no network', () => {
    const source = read('account/index.mjs');
    expect(source).not.toMatch(/from ['"]hd-wallet-wasm['"]/u);
    expect(source).not.toMatch(/\bfetch\s*\(/u);
    expect(source).not.toMatch(/XMLHttpRequest|WebSocket|importScripts/u);
    expect(source).not.toMatch(/^import[^\n]*['"]\.\.\/src\//mu);
    expect(source).not.toMatch(/^import[^\n]*['"]\.\.\/origin-app\//mu);
  });

  it('is published as its own export subpath and built as its own entry', () => {
    const pkg = JSON.parse(read('package.json'));
    expect(pkg.exports['./account']).toEqual({
      types: './dist/account/index.d.ts',
      import: './dist/account/index.js',
    });
    const build = read('scripts/build-release.mjs');
    expect(build).toContain("['account/index.mjs', 'account/index.js']");
    expect(read('test/bundle-boundaries.test.mjs')).toContain("'account/index.js'");
  });
});
