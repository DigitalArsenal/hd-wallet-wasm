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

// The bootstrap is src/landing.js, loaded by index.html as an external
// module (the page's Content-Security-Policy allows no inline script).
function bootstrapScript() {
  const html = read('index.html');
  expect(html).toContain('<script type="module" src="./src/landing.js"></script>');
  expect([...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>/gu)]).toHaveLength(0);
  const source = read('src/landing.js');
  expect(source).toContain("from './app.js'");
  return source;
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
async function runBootstrap({ windowHooks = {}, ids = [], framed = false, topThrows = false } = {}) {
  const elements = new Map(ids.map((id) => [id, new StubElement(id)]));
  const created = [];
  const body = {
    tagName: 'BODY',
    children: null,
    replaceChildren(...nodes) { this.children = nodes; },
  };
  const document = {
    body,
    getElementById: (id) => elements.get(id) ?? null,
    createElement(tag) {
      const node = {
        tag,
        attributes: {},
        children: [],
        textContent: '',
        setAttribute(name, value) { this.attributes[name] = value; },
        append(...nodes) { this.children.push(...nodes); },
      };
      created.push(node);
      return node;
    },
  };
  const window = { ...windowHooks, location: { href: 'https://wallet.example/' } };
  window.self = window;
  if (topThrows) {
    Object.defineProperty(window, 'top', { get() { throw new Error('SecurityError'); } });
  } else {
    window.top = framed ? { framedBy: 'attacker' } : window;
  }
  const calls = { init: [], createWalletUI: [], initI18n: 0, controls: [] };
  const controls = {
    openLogin: () => calls.controls.push(['openLogin']),
    openAccount: (section) => calls.controls.push(['openAccount', section]),
    closeAccount: () => calls.controls.push(['closeAccount']),
    logout: () => calls.controls.push(['logout']),
    destroy: () => calls.controls.push(['destroy']),
  };
  const modules = {
    './i18n.js': {
      applyTranslations() {},
      initI18n() { calls.initI18n += 1; },
    },
    './app.js': {
      async init(...args) { calls.init.push(args); return controls; },
      async createWalletUI(...args) {
        calls.createWalletUI.push(args);
        throw new Error('INVALID_TRANSACTION');
      },
    },
  };
  const script = bootstrapScript().replace(
    /import\s*\{([^}]*)\}\s*from\s*'([^']+)';/gu,
    (_match, names, specifier) => `const {${names}} = __modules[${JSON.stringify(specifier)}];`,
  );
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  await new AsyncFunction('window', 'document', '__modules', script)(window, document, modules);
  // Let init(...).then(...) settle.
  await new Promise((resolveTick) => setTimeout(resolveTick, 0));
  return { calls, elements, window, body, created };
}

describe('landing page bootstrap', () => {
  it('boots the in-page demo with init(document.body, opts), never the transaction app', async () => {
    const { calls, body } = await runBootstrap();

    expect(calls.createWalletUI).toHaveLength(0);
    expect(calls.init).toHaveLength(1);
    const [root, options] = calls.init[0];
    expect(root).toBe(body);
    expect(body.children).toBeNull();
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
    // autoOpenWallet was read and ignored in 2.x; 3.0 no longer passes it.
    expect(calls.init[0][1]).toEqual({
      onLogin,
      openAccountAfterLogin: false,
    });
  });

  it('hands __sdnWalletReady the controls init() resolves to', async () => {
    let ui = null;
    const { calls } = await runBootstrap({
      windowHooks: { __sdnWalletReady: (value) => { ui = value; } },
    });

    expect(ui).not.toBeNull();
    expect(Object.isFrozen(ui)).toBe(true);
    expect(Object.keys(ui).sort()).toEqual(['closeAccount', 'destroy', 'logout', 'openAccount', 'openLogin']);

    ui.openLogin();
    ui.openAccount('messages');
    ui.closeAccount();
    ui.logout();
    ui.destroy();
    expect(calls.controls).toEqual([
      ['openLogin'],
      ['openAccount', 'messages'],
      ['closeAccount'],
      ['logout'],
      ['destroy'],
    ]);
  });
});

describe('landing page in a frame (SEC-053)', () => {
  it('refuses to start the wallet inside a frame and links to the page on its own', async () => {
    const { calls, body } = await runBootstrap({ framed: true });
    expect(calls.init).toHaveLength(0);
    expect(calls.initI18n).toBe(0);
    expect(body.children).toHaveLength(1);
    const [notice] = body.children;
    expect(notice.attributes.role).toBe('alert');
    expect(notice.textContent).toContain('does not run inside another site');
    const link = notice.children.find((child) => child.tag === 'a');
    expect(link.href).toBe('https://wallet.example/');
    expect(link.target).toBe('_top');
  });

  it('treats an unreadable (cross-origin) parent as a frame', async () => {
    const { calls, body } = await runBootstrap({ topThrows: true });
    expect(calls.init).toHaveLength(0);
    expect(body.children[0].attributes.role).toBe('alert');
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

  it('injects the template, wires the login handlers and resolves to the host controls', () => {
    const init = functionBody('export async function init(');
    expect(init).toContain('appendTrustedStaticTemplate(container, getModalHTML())');
    expect(init).toContain('setupLoginHandlers();');
    expect(init).toContain('setupMainAppHandlers();');
    for (const name of ['openAccount', 'closeAccount', 'openLogin', 'logout', 'destroy']) {
      expect(init).toContain(`${name}: (`);
    }
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
