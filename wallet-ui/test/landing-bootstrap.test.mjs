// The landing page (index.html, built into docs/ and served at
// wallet.spacedatanetwork.org) must boot the in-page demo through init().
// From 26d8d81 until this test it booted createWalletUI(), the wallet-origin
// transaction app, which only serves /transaction/<id> requests: the page
// loaded without an error, but Login and Try Interactive Demo did nothing and
// no mnemonic could be generated.
//
// The bootstrap script is run here against a hand-rolled DOM stub (the package
// ships no DOM test environment; see account-view.test.js), with its imports
// replaced by recording stubs. The init() wiring it relies on is pinned from
// the source and the modal template.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { getModalHTML } from '../src/template.js';

const ROOT = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

function bootstrapScript() {
  const html = read('index.html');
  const scripts = [...html.matchAll(/<script type="module">([\s\S]*?)<\/script>/gu)]
    .map((match) => match[1])
    .filter((source) => source.includes("from './src/app.js'"));
  expect(scripts).toHaveLength(1);
  return scripts[0];
}

class StubElement {
  constructor(id) {
    this.id = id;
    this.style = {};
    this.clicks = 0;
    this.removed = false;
    this.classes = new Set();
    this.classList = {
      add: (token) => this.classes.add(token),
      contains: (token) => this.classes.has(token),
      remove: (token) => this.classes.delete(token),
    };
  }

  click() { this.clicks += 1; }

  remove() { this.removed = true; }
}

// Runs the bootstrap with each `import { a, b } from './x.js'` bound to the
// named exports in `modules`; a name a module does not export is undefined,
// so a bootstrap that calls it throws.
async function runBootstrap({ windowHooks = {}, ids = [] } = {}) {
  const elements = new Map(ids.map((id) => [id, new StubElement(id)]));
  const document = {
    body: { tagName: 'BODY' },
    getElementById: (id) => elements.get(id) ?? null,
  };
  const window = { ...windowHooks };
  const calls = { init: [], createWalletUI: [], initI18n: 0 };
  const modules = {
    './src/i18n.js': {
      applyTranslations() {},
      initI18n() { calls.initI18n += 1; },
    },
    './src/app.js': {
      async init(...args) { calls.init.push(args); },
      async createWalletUI(...args) {
        calls.createWalletUI.push(args);
        throw new Error('INVALID_TRANSACTION');
      },
    },
  };
  const body = bootstrapScript().replace(
    /import\s*\{([^}]*)\}\s*from\s*'([^']+)';/gu,
    (_match, names, specifier) => `const {${names}} = __modules[${JSON.stringify(specifier)}];`,
  );
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  await new AsyncFunction('window', 'document', '__modules', body)(window, document, modules);
  // Let init(...).then(...) settle.
  await new Promise((resolveTick) => setTimeout(resolveTick, 0));
  return { calls, elements, window };
}

describe('landing page bootstrap', () => {
  it('boots the in-page demo with init(document.body, opts), never the transaction app', async () => {
    const { calls } = await runBootstrap();

    expect(calls.createWalletUI).toHaveLength(0);
    expect(calls.init).toHaveLength(1);
    const [root, options] = calls.init[0];
    expect(root).toEqual({ tagName: 'BODY' });
    expect(options).toEqual({});
    expect(calls.initI18n).toBe(1);
  });

  it('passes the SDN host hooks through as init() options', async () => {
    const onLogin = () => {};
    const { calls } = await runBootstrap({
      windowHooks: {
        __sdnAutoOpen: true,
        __sdnOnLogin: onLogin,
        __sdnOpenAccountAfterLogin: false,
      },
    });

    expect(calls.init).toHaveLength(1);
    expect(calls.init[0][1]).toEqual({
      autoOpenWallet: true,
      onLogin,
      openAccountAfterLogin: false,
    });
  });

  it('hands __sdnWalletReady the controls hosts call once init() resolves', async () => {
    let ui = null;
    const { elements } = await runBootstrap({
      ids: ['nav-login', 'nav-logout', 'login-modal', 'keys-modal', 'hd-wallet-ui-container'],
      windowHooks: { __sdnWalletReady: (value) => { ui = value; } },
    });

    expect(ui).not.toBeNull();
    expect(Object.isFrozen(ui)).toBe(true);
    expect(Object.keys(ui).sort()).toEqual(['destroy', 'logout', 'openAccount', 'openLogin']);

    ui.openLogin();
    expect(elements.get('login-modal').classList.contains('active')).toBe(true);
    expect(elements.get('keys-modal').classList.contains('active')).toBe(false);

    // Signed in: the demo hides #nav-login, and openLogin shows the account.
    elements.get('login-modal').classList.remove('active');
    elements.get('nav-login').style.display = 'none';
    ui.openLogin();
    expect(elements.get('login-modal').classList.contains('active')).toBe(false);
    expect(elements.get('keys-modal').classList.contains('active')).toBe(true);

    ui.logout();
    expect(elements.get('nav-logout').clicks).toBe(1);
    ui.destroy();
    expect(elements.get('hd-wallet-ui-container').removed).toBe(true);
  });
});

describe('init() wiring the landing page relies on', () => {
  const app = read('src/app.js');

  function functionBody(name) {
    const start = app.indexOf(name);
    expect(start).toBeGreaterThanOrEqual(0);
    const next = app.indexOf('\nfunction ', start + name.length);
    const nextExport = app.indexOf('\nexport ', start + name.length);
    const ends = [next, nextExport].filter((index) => index > start);
    return app.slice(start, ends.length ? Math.min(...ends) : undefined);
  }

  it('injects the modal template and wires the login handlers', () => {
    const init = functionBody('export async function init(');
    expect(init).toContain('appendTrustedStaticTemplate(container, getModalHTML())');
    expect(init).toContain('setupLoginHandlers();');
    expect(init).toContain('setupMainAppHandlers();');
  });

  it('opens #login-modal from both #nav-login and #hero-login', () => {
    const handlers = functionBody('function setupMainAppHandlers(');
    for (const id of ['nav-login', 'hero-login']) {
      expect(handlers).toMatch(new RegExp(
        `\\$\\('${id}'\\)\\?\\.addEventListener\\('click', \\(\\) => \\{\\s*\\$\\('login-modal'\\)\\?\\.classList\\.add\\('active'\\);`,
        'u',
      ));
    }
    const html = read('index.html');
    expect(html).toContain('<button id="nav-login"');
    expect(html).toContain('<button id="hero-login"');
  });

  it('lets the login modal generate a mnemonic', () => {
    const template = getModalHTML();
    expect(template).toContain('id="login-modal"');
    expect(template).toContain('data-method="seed"');
    expect(template).toContain('id="seed-phrase"');
    expect(template).toContain('id="generate-seed"');
    const login = functionBody('function setupLoginHandlers(');
    expect(login).toMatch(/\$\('generate-seed'\)\?\.addEventListener\('click'[\s\S]*?generateSeedPhrase\(\)/u);
  });
});
