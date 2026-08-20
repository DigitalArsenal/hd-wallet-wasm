import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postcss from 'postcss';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const SOURCE_CSS = path.join(ROOT, 'styles', 'main.css');
const OUT_CSS = path.join(ROOT, 'styles', 'widget.css');

// Scoped styles are applied only within this container.
const NAMESPACE = '#hd-wallet-ui-container';
const KEYFRAMES_PREFIX = 'hdw-';

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
 * - `body:has(...)` -> keep `body` but scope the `:has()` and descendants to our container
 */
function prefixSelector(selector) {
  const parts = postcss.list.comma(selector);
  const out = parts.map((part) => {
    const s = part.trim();
    if (!s) return s;

    if (s === ':root') return NAMESPACE;
    if (s === 'html' || s === 'body') return NAMESPACE;

    if (s.startsWith('body:has(')) {
      // Make sure :has() only triggers based on our UI subtree.
      const scopedHas = s.replace(/body:has\(([^)]*)\)/g, (_m, inner) => {
        const innerTrimmed = String(inner || '').trim();
        if (!innerTrimmed) return `body:has(${NAMESPACE})`;
        if (innerTrimmed.startsWith(NAMESPACE)) return `body:has(${innerTrimmed})`;
        return `body:has(${NAMESPACE} ${innerTrimmed})`;
      });

      // If there are descendant selectors after body:has(...), prefix them too.
      // Example: `body:has(.modal.active) .nav-bar` =>
      //          `body:has(#hd-wallet-ui-container .modal.active) #hd-wallet-ui-container .nav-bar`
      const idx = scopedHas.indexOf(') ');
      if (idx === -1) return scopedHas;
      const head = scopedHas.slice(0, idx + 1);
      const tail = scopedHas.slice(idx + 2).trim();
      if (!tail) return head;
      if (tail.startsWith(NAMESPACE)) return `${head} ${tail}`;
      return `${head} ${NAMESPACE} ${tail}`;
    }

    if (s.startsWith(NAMESPACE)) return s;
    return `${NAMESPACE} ${s}`;
  });
  return out.join(', ');
}

async function main() {
  let raw = await fs.readFile(SOURCE_CSS, 'utf8');
  // Inline relative @imports (e.g. external-panel.css) so the widget build
  // namespaces ONE flat sheet — a raw @import would ship an unresolved
  // relative path inside the published widget.css.
  for (const match of raw.matchAll(/@import\s+url\(\s*['"]?(\.\/[^'")]+)['"]?\s*\)\s*;/g)) {
    const imported = await fs.readFile(path.join(ROOT, 'styles', match[1]), 'utf8');
    raw = raw.replace(match[0], imported);
  }
  const root = postcss.parse(raw, { from: SOURCE_CSS });

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

  await fs.writeFile(OUT_CSS, banner + root.toString(), 'utf8');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
