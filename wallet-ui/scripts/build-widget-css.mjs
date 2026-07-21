import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postcss from 'postcss';

const MODULE_PATH = fileURLToPath(import.meta.url);
const __dirname = path.dirname(MODULE_PATH);
const ROOT = path.resolve(__dirname, '..');

const SOURCE_CSS = path.join(ROOT, 'styles', 'main.css');
const OUT_CSS = path.join(ROOT, 'styles', 'widget.css');

// Scoped styles are applied only within this container.
const NAMESPACE = '#hd-wallet-ui-container';
const KEYFRAMES_PREFIX = 'hdw-';
const RTL_HOST = 'html[dir="rtl"]';
const RTL_HOST_PATTERN = /^html\s*\[\s*dir\s*=\s*(?:"rtl"|'rtl'|rtl)\s*\](?=$|\s)/i;

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isInsideKeyframes(node) {
  let cur = node.parent;
  while (cur) {
    if (cur.type === 'atrule' && /keyframes$/i.test(cur.name)) return true;
    cur = cur.parent;
  }
  return false;
}

/**
 * Prefix a selector list with the namespace, while handling a few special cases:
 * - `:root` -> namespace element (to scope CSS variables)
 * - `html` / `body` -> namespace element (avoid touching host page)
 * - equivalent `html[dir="rtl"] ...` forms -> keep the host direction selector above the namespace
 * - `body:has(...)` -> keep `body` but scope the `:has()` and descendants to our container
 */
export function prefixSelector(selector) {
  const parts = postcss.list.comma(selector);
  const out = parts.map((part) => {
    const s = part.trim();
    if (!s) return s;

    if (s === ':root') return NAMESPACE;
    if (s === 'html' || s === 'body') return NAMESPACE;

    const rtlHostMatch = s.match(RTL_HOST_PATTERN);
    if (rtlHostMatch) {
      const tail = s.slice(rtlHostMatch[0].length).trim();
      if (!tail) return `${RTL_HOST} ${NAMESPACE}`;
      if (tail.startsWith(NAMESPACE)) return `${RTL_HOST} ${tail}`;
      return `${RTL_HOST} ${NAMESPACE} ${tail}`;
    }

    if (s.startsWith('body:has(')) {
      // Make sure :has() only triggers based on our UI subtree.
      const openIndex = s.indexOf('(');
      const closeIndex = findMatchingParen(s, openIndex);
      if (closeIndex === -1) return `${NAMESPACE} ${s}`;

      const inner = s.slice(openIndex + 1, closeIndex).trim();
      const scopedInner = !inner
        ? NAMESPACE
        : (inner.startsWith(NAMESPACE) ? inner : `${NAMESPACE} ${inner}`);
      const scopedHas = `${s.slice(0, openIndex + 1)}${scopedInner})`;

      // If there are descendant selectors after body:has(...), prefix them too.
      // Example: `body:has(.modal.active) .nav-bar` =>
      //          `body:has(#hd-wallet-ui-container .modal.active) #hd-wallet-ui-container .nav-bar`
      const tail = s.slice(closeIndex + 1).trim();
      if (!tail) return scopedHas;
      if (tail.startsWith(NAMESPACE)) return `${scopedHas} ${tail}`;
      return `${scopedHas} ${NAMESPACE} ${tail}`;
    }

    if (s.startsWith(NAMESPACE)) return s;
    return `${NAMESPACE} ${s}`;
  });
  return out.join(', ');
}

function findMatchingParen(value, openIndex) {
  let depth = 0;
  let quote = null;
  let escaped = false;

  for (let index = openIndex; index < value.length; index += 1) {
    const char = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '(') {
      depth += 1;
    } else if (char === ')') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }

  return -1;
}

export async function buildWidgetCss({ sourcePath = SOURCE_CSS, outputPath = OUT_CSS } = {}) {
  const raw = await fs.readFile(sourcePath, 'utf8');
  const root = postcss.parse(raw, { from: sourcePath });

  // Rename keyframes to avoid global collisions.
  const keyframeMap = new Map();
  root.walkAtRules((atRule) => {
    if (!/keyframes$/i.test(atRule.name)) return;
    const name = String(atRule.params || '').trim();
    if (!name) return;
    if (name.startsWith(KEYFRAMES_PREFIX)) return;
    const next = `${KEYFRAMES_PREFIX}${name}`;
    keyframeMap.set(name, next);
    atRule.params = next;
  });

  // Prefix selectors.
  root.walkRules((rule) => {
    if (isInsideKeyframes(rule)) return;
    rule.selector = prefixSelector(rule.selector);
  });

  // Update animation references to renamed keyframes.
  if (keyframeMap.size > 0) {
    root.walkDecls((decl) => {
      if (decl.prop !== 'animation' && decl.prop !== 'animation-name') return;
      let v = decl.value;
      for (const [oldName, newName] of keyframeMap.entries()) {
        v = v.replace(new RegExp(`\\b${escapeRegExp(oldName)}\\b`, 'g'), newName);
      }
      decl.value = v;
    });
  }

  const banner = `/*\n` +
    ` * Generated file: namespaced styles for embedding hd-wallet-ui.\n` +
    ` *\n` +
    ` * - Scopes all selectors under ${NAMESPACE} to avoid host-page CSS collisions.\n` +
    ` * - Renames @keyframes to "${KEYFRAMES_PREFIX}*" to avoid global keyframe collisions.\n` +
    ` *\n` +
    ` * Source: styles/main.css\n` +
    ` * Regenerate: npm run build:widget-css\n` +
    ` */\n\n`;

  await fs.writeFile(outputPath, banner + root.toString(), 'utf8');
}

if (process.argv[1] && path.resolve(process.argv[1]) === MODULE_PATH) {
  buildWidgetCss().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
