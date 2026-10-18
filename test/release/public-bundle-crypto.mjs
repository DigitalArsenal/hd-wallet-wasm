/**
 * Structural Web Crypto gate for the public wallet client bundles.
 *
 * The public client may hold exactly one key of its own: the one-use X25519
 * reply key that receives sealed plaintext from the wallet. Everything else
 * it does with Web Crypto must follow from that key. The checks below parse
 * the bundle (minified or not) and bind each Web Crypto call site to that
 * shape, so a renamed identifier cannot hide a new key, KDF or export:
 *
 *   generate-key        one generateKey: X25519, extractable false, ['deriveBits']
 *   export-key          one exportKey: 'raw' of that pair's publicKey
 *   private-key-escape  the pair's privateKey is held once and used only as the
 *                       base key of the X25519 deriveBits
 *   derive-bits         deriveBits is X25519 (ephemeral private key against the
 *                       imported wallet reply public key) or HKDF over that output
 *   hkdf-context        HKDF info is only a reply-cipher label, never a wallet
 *                       derivation context (sdn-field-encryption, BIP32/SLIP10)
 *   kdf-literal         no PBKDF2/HMAC algorithm; 'HKDF' only in the reply cipher
 *   import-key          importKey is 'raw', non-extractable, and either an X25519
 *                       public key or a key made from the reply ECDH output
 *   decrypt             decrypt is AES-CTR with a key made from the reply ECDH output
 *   forbidden-method    no deriveKey, wrapKey, unwrapKey, sign, verify or encrypt
 *   subtle-escape       crypto.subtle is used only through allowlisted methods
 *   computed-guarded-name  no computed access to subtle, a key method or privateKey
 *   guarded-name-literal   no string literal naming a key method or privateKey
 *   inventory           the key-related call sites are exactly the allowlist below
 */
import { parseAst } from 'vite';

/** Every key-related Web Crypto call in a public bundle, normalized (identifiers are `_`). */
export const REPLY_CIPHER_CALL_SITES = Object.freeze([
  'decrypt({counter:_,length:128,name:"AES-CTR"},_,_)',
  'deriveBits({hash:"SHA-256",info:_,name:"HKDF",salt:new _(0)},_,_)',
  'deriveBits({name:"X25519",public:_},_,256)',
  'exportKey("raw",_.publicKey)',
  'generateKey({name:"X25519"},false,["deriveBits"])',
  'importKey("raw",_,"AES-CTR",false,["decrypt"])',
  'importKey("raw",_,"HKDF",false,["deriveBits"])',
  'importKey("raw",_(_),{name:"X25519"},false,[])',
].sort());

/** The only HKDF info labels the public client may use (sdn-wallet-reply/v1 cipher). */
export const REPLY_LABELS = Object.freeze(['flatbuffers-field', 'flatbuffers-iv', 'sdn-wallet-reply/v1']);

const WALLET_CONTEXT = /sdn-field-encryption|(?:^|[^A-Za-z])m\/\d|seed/iu;
for (const label of REPLY_LABELS) {
  if (WALLET_CONTEXT.test(label)) throw new Error(`reply label ${label} names a wallet context`);
}

const SUBTLE_METHODS = new Set([
  'decrypt', 'deriveBits', 'deriveKey', 'digest', 'encrypt', 'exportKey',
  'generateKey', 'importKey', 'sign', 'unwrapKey', 'verify', 'wrapKey',
]);
const ALLOWED_SUBTLE_METHODS = new Set(['decrypt', 'deriveBits', 'digest', 'exportKey', 'generateKey', 'importKey']);
/**
 * Names that are never ordinary words: no other object may carry them.
 * (unwrapKey is also the public client's FlatSQL operation, so only its
 * Web Crypto form is refused, by forbidden-method.)
 */
const KEY_METHODS = new Set(['deriveBits', 'deriveKey', 'exportKey', 'generateKey', 'importKey', 'wrapKey']);
const GUARDED_NAMES = new Set([...KEY_METHODS, 'privateKey', 'subtle']);

function isNode(value) {
  return value !== null && typeof value === 'object' && typeof value.type === 'string';
}

function children(node) {
  const out = [];
  for (const key of Object.keys(node)) {
    if (key === 'parent') continue;
    const value = node[key];
    if (Array.isArray(value)) for (const item of value) { if (isNode(item)) out.push(item); }
    else if (isNode(value)) out.push(value);
  }
  return out;
}

function index(ast) {
  const all = [];
  const stack = [[ast, null]];
  while (stack.length) {
    const [node, parent] = stack.pop();
    Object.defineProperty(node, 'parent', { value: parent, enumerable: false, configurable: true });
    all.push(node);
    for (const child of children(node)) stack.push([child, node]);
  }
  return all;
}

const FUNCTION_TYPES = new Set(['ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression']);

function bindingNames(pattern, out = []) {
  if (!pattern) return out;
  if (pattern.type === 'Identifier') out.push(pattern);
  else if (pattern.type === 'AssignmentPattern') bindingNames(pattern.left, out);
  else if (pattern.type === 'RestElement') bindingNames(pattern.argument, out);
  else if (pattern.type === 'ArrayPattern') for (const element of pattern.elements) bindingNames(element, out);
  else if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties) bindingNames(property.type === 'RestElement' ? property : property.value, out);
  }
  return out;
}

function declare(scope, pattern, value) {
  for (const id of bindingNames(pattern)) if (!scope.has(id.name)) scope.set(id.name, value);
}

function declareStatements(scope, statements, kinds) {
  for (const statement of statements) {
    const declaration = statement?.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
    if (!declaration) continue;
    if (declaration.type === 'VariableDeclaration' && kinds.includes(declaration.kind)) {
      for (const declarator of declaration.declarations) declare(scope, declarator.id, { kind: 'var', declarator });
    } else if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && declaration.id) {
      declare(scope, declaration.id, { kind: 'function', fn: declaration });
    }
  }
}

const scopes = new WeakMap();

/** The names a scope-creating node declares, computed once per node. */
function scopeOf(node) {
  if (scopes.has(node)) return scopes.get(node);
  const scope = new Map();
  if (FUNCTION_TYPES.has(node.type)) {
    node.params.forEach((param, position) => declare(scope, param, { kind: 'param', fn: node, position }));
    if (node.type === 'FunctionExpression' && node.id) declare(scope, node.id, { kind: 'function', fn: node });
    const stack = [node.body];
    while (stack.length) {
      const current = stack.pop();
      if (!isNode(current) || (current !== node.body && FUNCTION_TYPES.has(current.type))) continue;
      if (current.type === 'VariableDeclaration' && current.kind === 'var') {
        for (const declarator of current.declarations) declare(scope, declarator.id, { kind: 'var', declarator });
      }
      stack.push(...children(current));
    }
  } else if (node.type === 'BlockStatement' || node.type === 'Program' || node.type === 'StaticBlock') {
    declareStatements(scope, node.body, node.type === 'Program' ? ['const', 'let', 'var'] : ['const', 'let']);
  } else if (node.type === 'ForStatement' || node.type === 'ForInStatement' || node.type === 'ForOfStatement') {
    const init = node.type === 'ForStatement' ? node.init : node.left;
    if (init?.type === 'VariableDeclaration') declareStatements(scope, [init], ['const', 'let', 'var']);
  } else if (node.type === 'CatchClause' && node.param) {
    declare(scope, node.param, { kind: 'catch' });
  }
  scopes.set(node, scope);
  return scope;
}

/** The declaration an identifier reference resolves to, by lexical scope. */
function resolve(identifier) {
  for (let node = identifier.parent; node; node = node.parent) {
    const found = scopeOf(node).get(identifier.name);
    if (found) return found;
  }
  return null;
}

/** True when an Identifier names a binding or a property, not a value reference. */
function isNotReference(node) {
  const parent = node.parent;
  if (!parent) return true;
  if (parent.type === 'VariableDeclarator' && parent.id === node) return true;
  if (FUNCTION_TYPES.has(parent.type) && (parent.params.includes(node) || parent.id === node)) return true;
  if ((parent.type === 'ClassDeclaration' || parent.type === 'ClassExpression') && parent.id === node) return true;
  if (parent.type === 'MemberExpression' && parent.property === node && !parent.computed) return true;
  if ((parent.type === 'Property' || parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition')
    && parent.key === node && !parent.computed && !parent.shorthand) return true;
  if (parent.type === 'AssignmentPattern' && parent.left === node) return true;
  if (parent.type === 'RestElement' || parent.type === 'ArrayPattern' || parent.type === 'CatchClause') return true;
  if (parent.type === 'Property' && parent.parent?.type === 'ObjectPattern') return true;
  if (parent.type === 'LabeledStatement' || parent.type === 'BreakStatement' || parent.type === 'ContinueStatement') return true;
  return false;
}

function unwrap(node) {
  let current = node;
  while (current && (current.type === 'ChainExpression' || current.type === 'AwaitExpression')) {
    current = current.type === 'ChainExpression' ? current.expression : current.argument;
  }
  return current;
}

function propertyName(member) {
  if (member?.type !== 'MemberExpression') return null;
  if (!member.computed && member.property.type === 'Identifier') return member.property.name;
  return null;
}

function constantString(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantString(node.left);
    const right = constantString(node.right);
    return left !== null && right !== null ? left + right : null;
  }
  return null;
}

function constantBoolean(node) {
  if (node?.type === 'Literal' && typeof node.value === 'boolean') return node.value;
  if (node?.type === 'UnaryExpression' && node.operator === '!' && node.argument.type === 'Literal') {
    return !node.argument.value;
  }
  return null;
}

/** A rename-proof rendering of an expression: identifiers become `_`. */
export function shape(node) {
  if (!node) return '';
  switch (node.type) {
    case 'Literal':
      if (node.regex) return `/${node.regex.pattern}/${node.regex.flags}`;
      return JSON.stringify(node.value);
    case 'Identifier':
      return '_';
    case 'UnaryExpression': {
      const value = constantBoolean(node);
      return value === null ? `${node.operator}${shape(node.argument)}` : String(value);
    }
    case 'ChainExpression':
      return shape(node.expression);
    case 'AwaitExpression':
      return `await ${shape(node.argument)}`;
    case 'MemberExpression':
      return node.computed ? `${shape(node.object)}[${shape(node.property)}]` : `${shape(node.object)}.${node.property.name}`;
    case 'CallExpression':
      return `${shape(node.callee)}(${node.arguments.map(shape).join(',')})`;
    case 'NewExpression':
      return `new ${shape(node.callee)}(${node.arguments.map(shape).join(',')})`;
    case 'ArrayExpression':
      return `[${node.elements.map(shape).join(',')}]`;
    case 'ObjectExpression':
      return `{${node.properties.map((property) => (property.type === 'Property'
        ? `${property.computed ? `[${shape(property.key)}]` : (property.key.name ?? property.key.value)}:${shape(property.value)}`
        : `...${shape(property.argument)}`)).join(',')}}`;
    default:
      return node.type;
  }
}

function objectProperties(node) {
  if (node?.type !== 'ObjectExpression') return null;
  const out = new Map();
  for (const property of node.properties) {
    if (property.type !== 'Property' || property.computed || property.kind !== 'init') return null;
    out.set(property.key.name ?? property.key.value, property.value);
  }
  return out;
}

function hasExactKeys(map, keys) {
  return map !== null && map.size === keys.length && keys.every((key) => map.has(key));
}

function isStringArray(node, values) {
  return node?.type === 'ArrayExpression'
    && node.elements.length === values.length
    && node.elements.every((element, position) => constantString(element) === values[position]);
}

/**
 * Check one bundle's source. Returns a list of { check, message } violations;
 * an empty list means the bundle holds no wallet secret and only the reply key.
 */
export function checkPublicBundleCrypto(source) {
  const ast = parseAst(source);
  const nodes = index(ast);
  const violations = [];
  const fail = (check, node, message) => {
    violations.push({ check, message: `${message} at offset ${node?.start ?? '?'}: ${shape(node).slice(0, 160)}` });
  };

  const callsTo = new Map();
  for (const node of nodes) {
    if (node.type !== 'CallExpression' || unwrap(node.callee)?.type !== 'Identifier') continue;
    const target = resolve(unwrap(node.callee));
    const fn = target?.kind === 'function' ? target.fn
      : (target?.kind === 'var' && FUNCTION_TYPES.has(target.declarator.init?.type) ? target.declarator.init : null);
    if (!fn) continue;
    if (!callsTo.has(fn)) callsTo.set(fn, []);
    callsTo.get(fn).push(node);
  }
  const callTarget = (call) => {
    if (call?.type !== 'CallExpression' || unwrap(call.callee)?.type !== 'Identifier') return null;
    const target = resolve(unwrap(call.callee));
    if (target?.kind === 'function') return target.fn;
    if (target?.kind === 'var' && FUNCTION_TYPES.has(target.declarator.init?.type)) return target.declarator.init;
    return null;
  };

  /** Follow an expression to every value that can reach it (inits, call-site arguments). */
  const origins = (expression, seen = new Set()) => {
    const node = unwrap(expression);
    if (!node || seen.has(node)) return [];
    seen.add(node);
    if (node.type !== 'Identifier') return [node];
    const target = resolve(node);
    if (target?.kind === 'var') return target.declarator.init ? origins(target.declarator.init, seen) : [];
    if (target?.kind === 'param') {
      const calls = callsTo.get(target.fn) ?? [];
      if (calls.length === 0) return [node];
      return calls.flatMap((call) => origins(call.arguments[target.position], seen));
    }
    return [node];
  };
  const allOrigins = (expression, predicate) => {
    const found = origins(expression);
    return found.length > 0 && found.every(predicate);
  };

  const isSubtleOrigin = (node) => propertyName(node) === 'subtle';
  const isSubtle = (expression) => allOrigins(expression, isSubtleOrigin);

  // Web Crypto call sites: a non-computed member call whose object is crypto.subtle.
  const cryptoCalls = [];
  for (const node of nodes) {
    if (node.type !== 'CallExpression') continue;
    const callee = unwrap(node.callee);
    const method = propertyName(callee);
    if (!method || !SUBTLE_METHODS.has(method)) continue;
    if (isSubtle(callee.object)) cryptoCalls.push({ node, method });
    else if (KEY_METHODS.has(method)) fail('subtle-escape', node, `${method} on an object not proven to be crypto.subtle`);
  }
  const callsOf = (method) => cryptoCalls.filter((call) => call.method === method).map((call) => call.node);
  const isCryptoCall = (node, method) => node?.type === 'CallExpression'
    && cryptoCalls.some((call) => call.node === node && call.method === method);

  // generate-key
  const generated = callsOf('generateKey');
  const pairDeclarators = new Set();
  if (generated.length > 1) fail('generate-key', generated[1], 'more than one generateKey');
  for (const call of generated) {
    const [algorithm, extractable, usages] = call.arguments;
    const ok = call.arguments.length === 3
      && hasExactKeys(objectProperties(algorithm), ['name'])
      && constantString(objectProperties(algorithm).get('name')) === 'X25519'
      && constantBoolean(extractable) === false
      && isStringArray(usages, ['deriveBits']);
    if (!ok) fail('generate-key', call, 'generateKey must be X25519, extractable false, deriveBits only');
    const holder = call.parent?.type === 'AwaitExpression' ? call.parent.parent : null;
    if (holder?.type === 'VariableDeclarator' && holder.id.type === 'Identifier') pairDeclarators.add(holder);
    else fail('generate-key', call, 'the generated pair must be bound to one variable');
  }
  const isPair = (expression) => allOrigins(expression, (origin) => isCryptoCall(origin, 'generateKey'));

  // export-key
  const exported = callsOf('exportKey');
  if (exported.length > 1) fail('export-key', exported[1], 'more than one exportKey');
  for (const call of exported) {
    const [format, key] = call.arguments;
    const ok = call.arguments.length === 2 && constantString(format) === 'raw'
      && propertyName(unwrap(key)) === 'publicKey' && isPair(unwrap(key).object);
    if (!ok) fail('export-key', call, "exportKey must be 'raw' of the reply pair's publicKey");
  }

  // private-key-escape: the pair's privateKey is held once and reaches only the X25519 deriveBits.
  const privateReads = nodes.filter((node) => node.type === 'MemberExpression' && propertyName(node) === 'privateKey');
  const privateHolders = [];
  for (const read of privateReads) {
    const holder = read.parent;
    if (!isPair(read.object) || holder?.type !== 'VariableDeclarator' || holder.init !== read || holder.id.type !== 'Identifier') {
      fail('private-key-escape', read, 'privateKey is read only into one binding from the reply pair');
    } else privateHolders.push(holder);
  }
  if (privateHolders.length > 1) fail('private-key-escape', privateHolders[1], 'privateKey is held more than once');
  for (const node of nodes) {
    if ((node.type === 'Property' || node.type === 'PropertyDefinition' || node.type === 'MethodDefinition')
      && !node.computed && (node.key?.name ?? node.key?.value) === 'privateKey' && node.parent?.type !== 'ObjectPattern') {
      fail('private-key-escape', node, 'no object carries a privateKey property');
    }
  }
  const privateBindings = new Set();
  const isPrivateKeyRef = (expression) => allOrigins(expression, (origin) => privateReads.includes(origin));
  for (const node of nodes) {
    if (node.type !== 'Identifier' || isNotReference(node)) continue;
    const parent = node.parent;
    const target = resolve(node);
    if (target?.kind !== 'var' || !target.declarator.init || !isPrivateKeyRef(target.declarator.init)) continue;
    privateBindings.add(target.declarator);
    const allowed = (parent?.type === 'UnaryExpression' && parent.operator === '!')
      || (parent?.type === 'AssignmentExpression' && parent.left === node && parent.right.type === 'Literal' && parent.right.value === null)
      || (parent?.type === 'VariableDeclarator' && parent.init === node)
      || (parent?.type === 'CallExpression' && parent.arguments[1] === node && isCryptoCall(parent, 'deriveBits')
        && constantString(objectProperties(parent.arguments[0])?.get('name')) === 'X25519');
    if (!allowed) fail('private-key-escape', parent ?? node, 'the reply private key is used only by the X25519 deriveBits');
  }

  // Key provenance for import-key and decrypt: everything secret comes from the reply ECDH.
  const hkdfHelpers = new Set();
  const isEcdh = (call) => isCryptoCall(call, 'deriveBits')
    && constantString(objectProperties(call.arguments[0])?.get('name')) === 'X25519';
  const isHkdf = (call) => isCryptoCall(call, 'deriveBits')
    && constantString(objectProperties(call.arguments[0])?.get('name')) === 'HKDF';
  for (const call of callsOf('deriveBits')) {
    if (!isHkdf(call)) continue;
    let fn = call.parent;
    while (fn && !FUNCTION_TYPES.has(fn.type)) fn = fn.parent;
    if (fn) hkdfHelpers.add(fn);
  }
  const isReplySecretOrigin = (origin) => {
    const inner = origin.type === 'NewExpression' && origin.callee.type === 'Identifier'
      && origin.callee.name === 'Uint8Array' && origin.arguments.length === 1 ? unwrap(origin.arguments[0]) : origin;
    return isEcdh(inner) || isHkdf(inner) || hkdfHelpers.has(callTarget(inner));
  };
  const isReplySecret = (expression) => allOrigins(expression, isReplySecretOrigin);

  // hkdf-context: HKDF info is built only from reply-cipher labels.
  const isReplyLabelOrigin = (origin) => {
    if (origin.type === 'CallExpression' && propertyName(unwrap(origin.callee)) === 'encode') {
      const encoder = origins(unwrap(origin.callee).object);
      return encoder.length > 0
        && encoder.every((node) => node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'TextEncoder')
        && origin.arguments.length === 1 && REPLY_LABELS.includes(constantString(origin.arguments[0]));
    }
    if (origin.type === 'CallExpression' && callTarget(origin) && origin.arguments.length > 0) {
      return allOrigins(origin.arguments[0], isReplyLabelOrigin)
        && origin.arguments.slice(1).every((argument) => constantString(argument) === null);
    }
    return false;
  };

  // derive-bits
  for (const call of callsOf('deriveBits')) {
    const [algorithm, baseKey, length] = call.arguments;
    const properties = objectProperties(algorithm);
    const name = constantString(properties?.get('name'));
    if (name === 'X25519') {
      const peer = properties.get('public');
      const peerOk = hasExactKeys(properties, ['name', 'public']) && allOrigins(peer, (origin) => isCryptoCall(origin, 'importKey')
        && objectProperties(origin.arguments[2]) !== null
        && constantString(objectProperties(origin.arguments[2]).get('name')) === 'X25519');
      if (!peerOk) fail('derive-bits', call, 'X25519 deriveBits must use the imported wallet reply public key');
      if (unwrap(baseKey)?.type !== 'Identifier' || !privateBindings.has(resolve(unwrap(baseKey))?.declarator)) {
        fail('derive-bits', call, 'X25519 deriveBits must use the ephemeral reply private key');
      }
      if (!(length?.type === 'Literal' && length.value === 256)) fail('derive-bits', call, 'X25519 deriveBits is 256 bits');
    } else if (name === 'HKDF') {
      const keysOk = hasExactKeys(properties, ['hash', 'info', 'name', 'salt'])
        && constantString(properties.get('hash')) === 'SHA-256';
      if (!keysOk) fail('derive-bits', call, 'HKDF deriveBits must be SHA-256 with info and salt');
      if (!allOrigins(baseKey, (origin) => isCryptoCall(origin, 'importKey') && constantString(origin.arguments[2]) === 'HKDF')) {
        fail('derive-bits', call, 'HKDF deriveBits must use an HKDF key imported from the reply ECDH output');
      }
      if (properties?.has('info') && !allOrigins(properties.get('info'), isReplyLabelOrigin)) {
        fail('hkdf-context', call, `HKDF info must be one of ${REPLY_LABELS.join(', ')}`);
      }
    } else {
      fail('derive-bits', call, 'deriveBits is X25519 or HKDF only');
    }
  }

  // import-key
  for (const call of callsOf('importKey')) {
    const [format, keyData, algorithm, extractable, usages] = call.arguments;
    const algorithmName = constantString(algorithm) ?? constantString(objectProperties(algorithm)?.get('name'));
    let ok = call.arguments.length === 5 && constantString(format) === 'raw' && constantBoolean(extractable) === false;
    if (algorithmName === 'X25519') {
      ok &&= hasExactKeys(objectProperties(algorithm), ['name']) && isStringArray(usages, []);
    } else if (algorithmName === 'HKDF') {
      ok &&= constantString(algorithm) === 'HKDF' && isStringArray(usages, ['deriveBits']) && isReplySecret(keyData);
    } else if (algorithmName === 'AES-CTR') {
      ok &&= constantString(algorithm) === 'AES-CTR' && isStringArray(usages, ['decrypt']) && isReplySecret(keyData);
    } else ok = false;
    if (!ok) {
      fail('import-key', call, "importKey must be 'raw', non-extractable: an X25519 public key, or HKDF/AES-CTR from the reply ECDH");
    }
  }

  // decrypt
  for (const call of callsOf('decrypt')) {
    const [algorithm, key] = call.arguments;
    const properties = objectProperties(algorithm);
    const ok = hasExactKeys(properties, ['counter', 'length', 'name'])
      && constantString(properties.get('name')) === 'AES-CTR'
      && isReplySecret(properties.get('counter'))
      && allOrigins(key, (origin) => isCryptoCall(origin, 'importKey') && constantString(origin.arguments[2]) === 'AES-CTR');
    if (!ok) fail('decrypt', call, 'decrypt is AES-CTR with a key and counter from the reply ECDH');
  }

  // forbidden-method
  for (const { node, method } of cryptoCalls) {
    if (!ALLOWED_SUBTLE_METHODS.has(method)) fail('forbidden-method', node, `${method} is not allowed in a public bundle`);
  }

  // subtle-escape: crypto.subtle (and every alias of it) is used only through allowlisted calls.
  const checkSubtleUse = (node) => {
    let use = node;
    while (use.parent?.type === 'ChainExpression') use = use.parent;
    const parent = use.parent;
    const allowed = (parent?.type === 'MemberExpression' && parent.object === use && !parent.computed
        && ALLOWED_SUBTLE_METHODS.has(parent.property.name))
      || (parent?.type === 'VariableDeclarator' && parent.init === use)
      || (parent?.type === 'UnaryExpression' && (parent.operator === '!' || parent.operator === 'typeof'))
      || (parent?.type === 'CallExpression' && parent.arguments.includes(use) && callTarget(parent));
    if (!allowed) fail('subtle-escape', parent ?? use, 'crypto.subtle is used only through allowlisted methods');
  };
  for (const node of nodes) {
    if (node.type === 'MemberExpression' && propertyName(node) === 'subtle') checkSubtleUse(node);
    if (node.type !== 'Identifier' || isNotReference(node)) continue;
    const parent = node.parent;
    const target = resolve(node);
    if (target?.kind === 'var' && target.declarator.init && isSubtle(target.declarator.init)) checkSubtleUse(node);
    else if (target?.kind === 'param' && (callsTo.get(target.fn) ?? []).some((call) => {
      const argument = call.arguments[target.position];
      return argument && isSubtle(argument);
    })) checkSubtleUse(node);
  }

  // computed-guarded-name and guarded-name-literal
  for (const node of nodes) {
    if (node.type === 'MemberExpression' && node.computed) {
      const name = constantString(node.property);
      if (name !== null && GUARDED_NAMES.has(name)) fail('computed-guarded-name', node, `computed access to ${name}`);
    }
    if (node.type === 'Literal' && typeof node.value === 'string' && GUARDED_NAMES.has(node.value)) {
      const parent = node.parent;
      const isKey = (parent?.type === 'Property' || parent?.type === 'MethodDefinition') && parent.key === node && !parent.computed;
      const isUsage = node.value === 'deriveBits' && parent?.type === 'ArrayExpression'
        && (isCryptoCall(parent.parent, 'generateKey') || isCryptoCall(parent.parent, 'importKey'))
        && parent.parent.arguments.at(-1) === parent;
      if ((!isKey && !isUsage) || node.value === 'privateKey') fail('guarded-name-literal', node, `string literal ${node.value}`);
    }
  }

  // kdf-literal
  for (const node of nodes) {
    const value = node.type === 'Literal' && typeof node.value === 'string' ? node.value
      : (node.type === 'TemplateElement' ? node.value.cooked : null);
    if (value === null) continue;
    if (/^(?:PBKDF2|HMAC)$/iu.test(value)) fail('kdf-literal', node, `${value} is not allowed in a public bundle`);
    if (/^HKDF$/iu.test(value)) {
      const parent = node.parent;
      const asImport = parent?.type === 'CallExpression' && parent.arguments[2] === node && isCryptoCall(parent, 'importKey');
      const asDerive = parent?.type === 'Property' && parent.value === node && (parent.key.name ?? parent.key.value) === 'name'
        && parent.parent?.parent?.type === 'CallExpression' && parent.parent.parent.arguments[0] === parent.parent
        && isCryptoCall(parent.parent.parent, 'deriveBits');
      if (!asImport && !asDerive) fail('kdf-literal', node, 'HKDF appears only in the reply cipher');
    }
  }

  // inventory
  const inventory = cryptoCalls.filter(({ method }) => method !== 'digest')
    .map(({ node, method }) => `${method}(${node.arguments.map(shape).join(',')})`).sort();
  if (inventory.length > 0 && JSON.stringify(inventory) !== JSON.stringify(REPLY_CIPHER_CALL_SITES)) {
    violations.push({
      check: 'inventory',
      message: `key-related Web Crypto call sites differ from the allowlist:\n  ${inventory.join('\n  ')}`,
    });
  }
  return violations;
}

/** Throw with every violation when a public bundle breaks the reply-key boundary. */
export function assertPublicBundleCrypto(source, label) {
  const violations = checkPublicBundleCrypto(source);
  if (violations.length > 0) {
    throw new Error(`${label}: public-bundle Web Crypto boundary\n${violations
      .map(({ check, message }) => `- ${check}: ${message}`).join('\n')}`);
  }
}
