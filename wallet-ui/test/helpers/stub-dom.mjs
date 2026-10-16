// A small DOM for the account view tests.
//
// The package ships no DOM test environment on purpose (see account-view.test.js):
// adding jsdom would put a dependency into a lockfile that a signed release
// verifies byte for byte. The account view only needs the calls stubbed here,
// and the stub proves it uses no more than that. Markup sinks throw.

const VOID = new Set(['input', 'br', 'img', 'meta', 'link', 'hr', 'source']);

function camel(name) {
  return name.replace(/-([a-z])/gu, (_, c) => c.toUpperCase());
}

export class StubNode {
  constructor(tagName, ownerDocument) {
    this.tagName = String(tagName).toUpperCase();
    this.localName = String(tagName).toLowerCase();
    this.ownerDocument = ownerDocument;
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.style = {
      props: new Map(),
      setProperty: (name, value) => this.style.props.set(name, value),
      getPropertyValue: (name) => this.style.props.get(name) ?? '',
    };
    this._className = '';
    this._text = '';
    this.id = '';
    this.hidden = false;
    this.disabled = false;
    this.inert = false;
    this.type = '';
    this.title = '';
    this.value = '';
    this.checked = false;
    this.open = false;
    this.tabIndex = 0;
    this.files = null;
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
    return this._className.split(/\s+/u).filter(Boolean);
  }

  #setClasses(tokens) {
    this._className = [...new Set(tokens)].join(' ');
  }

  get className() { return this._className; }

  set className(value) { this._className = String(value ?? ''); }

  get children() { return this.childNodes.filter((node) => node.tagName !== '#TEXT'); }

  get firstChild() { return this.childNodes[0] ?? null; }

  get lastChild() { return this.childNodes[this.childNodes.length - 1] ?? null; }

  get nodeType() { return this.tagName === '#TEXT' ? 3 : 1; }

  get textContent() {
    if (this.tagName === '#TEXT') return this._text;
    return this._text + this.childNodes.map((c) => c.textContent).join('');
  }

  set textContent(value) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    this._text = value === undefined || value === null ? '' : String(value);
  }

  set innerHTML(_value) { throw new Error('HTML sink used'); }

  set outerHTML(_value) { throw new Error('HTML sink used'); }

  insertAdjacentHTML() { throw new Error('HTML sink used'); }

  append(...nodes) {
    for (const node of nodes) {
      if (node === null || node === undefined) continue;
      const child = typeof node === 'string' ? this.ownerDocument.createTextNode(node) : node;
      if (child.parentNode) child.remove();
      child.parentNode = this;
      this.childNodes.push(child);
    }
  }

  appendChild(node) {
    this.append(node);
    return node;
  }

  insertBefore(node, reference) {
    if (node.parentNode) node.remove();
    const index = this.childNodes.indexOf(reference);
    node.parentNode = this;
    if (index < 0) this.childNodes.push(node);
    else this.childNodes.splice(index, 0, node);
  }

  replaceChildren(...nodes) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    this._text = '';
    this.append(...nodes);
  }

  replaceWith(node) {
    if (!this.parentNode) return;
    const parent = this.parentNode;
    const index = parent.childNodes.indexOf(this);
    if (node.parentNode) node.remove();
    node.parentNode = parent;
    parent.childNodes.splice(index, 1, node);
    this.parentNode = null;
  }

  remove() {
    if (!this.parentNode) return;
    const index = this.parentNode.childNodes.indexOf(this);
    if (index >= 0) this.parentNode.childNodes.splice(index, 1);
    this.parentNode = null;
  }

  contains(node) {
    for (let current = node; current; current = current.parentNode) {
      if (current === this) return true;
    }
    return false;
  }

  setAttribute(name, value) {
    if (/^on/iu.test(name)) throw new Error(`unsafe attribute ${name}`);
    const text = String(value);
    this.attributes.set(name, text);
    if (name === 'id') this.id = text;
    else if (name === 'class') this._className = text;
    else if (name === 'hidden') this.hidden = true;
    else if (name === 'tabindex') this.tabIndex = Number(text);
    else if (name === 'type') this.type = text;
    else if (name.startsWith('data-')) this.dataset[camel(name.slice(5))] = text;
  }

  getAttribute(name) {
    if (name === 'id') return this.id || null;
    if (name === 'class') return this._className || null;
    if (name === 'type' && !this.attributes.has('type')) return this.type || null;
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  hasAttribute(name) {
    return this.getAttribute(name) !== null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === 'hidden') this.hidden = false;
  }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  removeEventListener(type, handler) {
    const list = this.listeners.get(type);
    if (list) this.listeners.set(type, list.filter((entry) => entry !== handler));
  }

  dispatch(type, init = {}) {
    const event = {
      type,
      target: this,
      currentTarget: this,
      defaultPrevented: false,
      propagationStopped: false,
      preventDefault() { this.defaultPrevented = true; },
      stopPropagation() { this.propagationStopped = true; },
      ...init,
    };
    for (let node = this; node; node = node.parentNode) {
      event.currentTarget = node;
      for (const handler of [...(node.listeners.get(type) ?? [])]) handler(event);
      if (event.propagationStopped || init.bubbles === false) break;
    }
    if (event.propagationStopped) return event;
    if (this.ownerDocument && this.ownerDocument !== this && init.bubbles !== false) {
      for (const handler of [...(this.ownerDocument.listeners.get(type) ?? [])]) handler(event);
    }
    return event;
  }

  click() {
    if (this.disabled) return;
    this.dispatch('click');
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }

  getBoundingClientRect() {
    return { top: 0, bottom: this.rectBottom ?? 0, left: 0, right: 0, width: 0, height: this.rectBottom ?? 0 };
  }

  descendants() {
    const out = [];
    for (const child of this.childNodes) out.push(child, ...child.descendants());
    return out;
  }

  matches(selector) {
    return selector.split(',').some((part) => matchesCompound(this, part.trim()));
  }

  querySelectorAll(selector) {
    const groups = selector.split(',').map((part) => part.trim().split(/\s+/u));
    return this.descendants().filter((node) => node.tagName !== '#TEXT' && groups.some((chain) => matchesChain(node, chain, this)));
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  closest(selector) {
    for (let node = this; node && node.tagName !== undefined; node = node.parentNode) {
      if (node.tagName !== '#TEXT' && node.tagName !== '#DOCUMENT' && node.matches(selector)) return node;
    }
    return null;
  }
}

function matchesCompound(node, compound) {
  if (!compound) return false;
  const parts = compound.match(/(\.[\w-]+|#[\w-]+|\[[^\]]+\]|^[a-zA-Z][\w-]*|:[\w-]+(?:\([^)]*\))?)/gu) ?? [];
  if (parts.join('') !== compound) return false;
  return parts.every((part) => {
    if (part.startsWith('.')) return node.classList.contains(part.slice(1));
    if (part.startsWith('#')) return node.id === part.slice(1);
    if (part.startsWith(':')) {
      if (part === ':checked') return node.checked === true;
      if (part.startsWith(':not(')) return !matchesCompound(node, part.slice(5, -1));
      return true;
    }
    if (part.startsWith('[')) {
      const body = part.slice(1, -1);
      const eq = body.indexOf('=');
      if (eq < 0) return node.getAttribute(body) !== null;
      const name = body.slice(0, eq);
      const want = body.slice(eq + 1).replace(/^["']|["']$/gu, '');
      if (name === 'hidden') return String(node.hidden) === want;
      return node.getAttribute(name) === want;
    }
    return node.localName === part.toLowerCase();
  });
}

function matchesChain(node, chain, scope) {
  if (!matchesCompound(node, chain[chain.length - 1])) return false;
  let index = chain.length - 2;
  let current = node.parentNode;
  while (index >= 0 && current && current !== scope.parentNode) {
    if (current.tagName !== '#DOCUMENT' && matchesCompound(current, chain[index])) index -= 1;
    current = current.parentNode;
  }
  return index < 0;
}

export class StubDocument extends StubNode {
  constructor() {
    super('#document', null);
    this.ownerDocument = this;
    this.tagName = '#DOCUMENT';
    this.body = new StubNode('body', this);
    this.body.parentNode = this;
    this.childNodes = [this.body];
    this.activeElement = this.body;
    this.defaultView = null;
  }

  createElement(tagName) {
    return new StubNode(tagName, this);
  }

  createElementNS(_ns, tagName) {
    return new StubNode(tagName, this);
  }

  createTextNode(text) {
    const node = new StubNode('#text', this);
    node._text = String(text);
    return node;
  }

  getElementById(id) {
    return this.descendants().find((node) => node.id === id) ?? null;
  }

  dispatch(type, init = {}) {
    const event = {
      type,
      target: this,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      stopPropagation() {},
      ...init,
    };
    for (const handler of [...(this.listeners.get(type) ?? [])]) handler(event);
    return event;
  }
}

/** A window stub with a location, a history and hashchange. */
export function stubWindow(doc, { hash = '', pathname = '/', search = '' } = {}) {
  const listeners = new Map();
  const history = {
    state: null,
    entries: [],
    replaceState(_state, _title, url) {
      history.entries.push(['replace', url]);
      const hashIndex = String(url).indexOf('#');
      win.location.hash = hashIndex >= 0 ? String(url).slice(hashIndex) : '';
    },
    pushState(_state, _title, url) {
      history.entries.push(['push', url]);
      const hashIndex = String(url).indexOf('#');
      win.location.hash = hashIndex >= 0 ? String(url).slice(hashIndex) : '';
    },
  };
  const win = {
    document: doc,
    location: { hash, pathname, search },
    history,
    navigator: {},
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    removeEventListener(type, handler) {
      const list = listeners.get(type);
      if (list) listeners.set(type, list.filter((entry) => entry !== handler));
    },
    fire(type, event = {}) {
      for (const handler of [...(listeners.get(type) ?? [])]) handler({ type, ...event });
    },
    /** Simulate the user moving the hash (Back, a link): fires hashchange. */
    navigate(nextHash) {
      win.location.hash = nextHash;
      win.fire('hashchange');
    },
  };
  doc.defaultView = win;
  return win;
}

/**
 * Parse a trusted static template (template.js) into stub nodes: tags,
 * attributes, text and comments. Enough for the wallet's own markup.
 */
export function parseTemplate(doc, source) {
  const root = doc.createElement('div');
  const stack = [root];
  const pattern = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>|([^<]+)/gu;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    const [all, closing, opening, attributeText, selfClosing, text] = match;
    const top = stack[stack.length - 1];
    if (all.startsWith('<!--')) continue;
    if (closing) {
      const name = closing.toLowerCase();
      for (let index = stack.length - 1; index > 0; index -= 1) {
        if (stack[index].localName === name) {
          stack.length = index;
          break;
        }
      }
      continue;
    }
    if (opening) {
      const node = doc.createElement(opening.toLowerCase());
      const attributes = /([^\s=>/]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/gu;
      let attribute;
      while ((attribute = attributes.exec(attributeText ?? '')) !== null) {
        const name = attribute[1];
        const value = attribute[3] ?? attribute[4] ?? attribute[5] ?? '';
        if (/^on/iu.test(name)) continue;
        node.setAttribute(name, decodeEntities(value));
        if (name === 'disabled') node.disabled = true;
      }
      top.append(node);
      if (!selfClosing && !VOID.has(node.localName)) stack.push(node);
      continue;
    }
    if (text && text.trim()) top.append(doc.createTextNode(decodeEntities(text)));
  }
  return root;
}

function decodeEntities(text) {
  return text
    .replace(/&ndash;/gu, '–')
    .replace(/&times;/gu, '×')
    .replace(/&amp;/gu, '&')
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"');
}

/** All the text under a node, with whitespace collapsed. */
export function textOf(node) {
  return String(node?.textContent ?? '').replace(/\s+/gu, ' ').trim();
}

/** The first descendant (or self) whose text contains `needle`. */
export function findByText(root, needle, tag = null) {
  return root.descendants().find((node) => node.tagName !== '#TEXT'
    && (!tag || node.localName === tag)
    && textOf(node) === needle) ?? null;
}

function shown(node, root) {
  for (let current = node; current && current !== root; current = current.parentNode) {
    if (current.hidden) return false;
  }
  return true;
}

/**
 * A visible button or link by its label (a person can only click what they
 * can see); mode chips (`.chip`) are not actions. Hidden controls are found
 * only when nothing visible matches.
 */
export function buttonByText(root, label) {
  const matches = root.descendants().filter((node) => (node.localName === 'button' || node.localName === 'a')
    && !node.classList.contains('chip')
    && textOf(node) === label);
  return matches.find((node) => shown(node, root)) ?? matches[0] ?? null;
}

export async function flush(times = 6) {
  for (let index = 0; index < times; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/** A Storage-shaped in-memory store (getItem / setItem / removeItem / key / length). */
export function memoryStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    get length() { return map.size; },
    key: (index) => [...map.keys()][index] ?? null,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    removeItem: (key) => { map.delete(key); },
    clear: () => map.clear(),
    entries: () => [...map.entries()],
    map,
  };
}

/** Wait until `check()` is truthy (or throw after `timeout` ms). */
export async function waitFor(check, { timeout = 5000, label = 'condition' } = {}) {
  const start = Date.now();
  for (;;) {
    const value = check();
    if (value) return value;
    if (Date.now() - start > timeout) throw new Error(`Timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** The value text of the hairline row labelled `label`. */
export function rowValue(root, label) {
  const row = root.querySelectorAll('.row').find((node) => textOf(node.querySelector('.row-label')) === label);
  return row ? textOf(row.querySelector('.row-value')) : null;
}
