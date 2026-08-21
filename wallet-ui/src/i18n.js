// Lightweight vanilla i18n runtime for the HD Wallet WASM site.
//
// Usage in HTML:
//   <h2 data-i18n="features.heading">Features</h2>          (textContent)
//   <p  data-i18n-html="adv.intro.desc">...<strong>..</strong></p>  (safe strong/code nodes only)
//   <input data-i18n-attr="placeholder:search.placeholder">  (attributes)
//
// The English text left in the HTML is the fallback if a key is missing.
import { LOCALES, LANGS, RTL_LANGS } from "./i18n-locales.js";

const STORAGE_KEY = "hdwallet.lang";

export function supportedLang(code) {
  const short = String(code || "").slice(0, 2).toLowerCase();
  return LOCALES[short] ? short : null;
}

export function currentLang() {
  const saved = supportedLang(localStorage.getItem(STORAGE_KEY));
  if (saved) return saved;
  const nav = supportedLang(navigator.language || navigator.userLanguage);
  return nav || "en";
}

// t(key) — translate a dynamic string (falls back to English, then the key).
export function t(key, lang = currentLang()) {
  const dict = LOCALES[lang] || LOCALES.en;
  return dict[key] ?? LOCALES.en[key] ?? key;
}

const INLINE_TOKENS = Object.freeze({
  "<strong>": Object.freeze({ close: false, tag: "strong" }),
  "</strong>": Object.freeze({ close: true, tag: "strong" }),
  "<code>": Object.freeze({ close: false, tag: "code" }),
  "</code>": Object.freeze({ close: true, tag: "code" }),
});

// Render the one intentionally rich locale surface without an HTML parser.
// Any attribute, unknown tag, or nesting error fails closed to literal text.
export function renderSafeInlineTranslation(element, value, documentObject = document) {
  const source = String(value);
  const roots = [];
  const stack = [{ children: roots, tag: null }];
  let offset = 0;
  let valid = true;
  while (offset < source.length && valid) {
    const opening = source.indexOf("<", offset);
    const textEnd = opening === -1 ? source.length : opening;
    if (textEnd > offset) {
      stack[stack.length - 1].children.push({ text: source.slice(offset, textEnd) });
    }
    if (opening === -1) break;
    const closing = source.indexOf(">", opening + 1);
    if (closing === -1) {
      valid = false;
      break;
    }
    const literal = source.slice(opening, closing + 1);
    const token = INLINE_TOKENS[literal];
    if (!token) {
      valid = false;
      break;
    }
    if (token.close) {
      if (stack.length === 1 || stack[stack.length - 1].tag !== token.tag) {
        valid = false;
        break;
      }
      stack.pop();
    } else {
      const node = { children: [], tag: token.tag };
      stack[stack.length - 1].children.push(node);
      stack.push(node);
    }
    offset = closing + 1;
  }
  if (stack.length !== 1) valid = false;
  if (!valid) {
    element.replaceChildren(documentObject.createTextNode(source));
    return false;
  }
  const materialize = (node) => {
    if (Object.hasOwn(node, "text")) return documentObject.createTextNode(node.text);
    const output = documentObject.createElement(node.tag);
    output.append(...node.children.map(materialize));
    return output;
  };
  element.replaceChildren(...roots.map(materialize));
  return true;
}

export function applyTranslations(lang = currentLang()) {
  const dict = LOCALES[lang] || LOCALES.en;
  const pick = (key) => dict[key] ?? LOCALES.en[key];

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const v = pick(el.getAttribute("data-i18n"));
    if (v != null) el.textContent = v;
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    const v = pick(el.getAttribute("data-i18n-html"));
    if (v != null) renderSafeInlineTranslation(el, v);
  });
  document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
    el.getAttribute("data-i18n-attr")
      .split(",")
      .forEach((pair) => {
        const [attr, key] = pair.split(":").map((s) => s.trim());
        const v = pick(key);
        if (["aria-label", "placeholder", "title"].includes(attr) && v != null) {
          el.setAttribute(attr, v);
        }
      });
  });

  const root = document.documentElement;
  root.lang = lang;
  root.dir = RTL_LANGS.includes(lang) ? "rtl" : "ltr";
}

export function setLanguage(lang) {
  const code = supportedLang(lang) || "en";
  localStorage.setItem(STORAGE_KEY, code);
  applyTranslations(code);
  const sel = document.getElementById("lang-switcher");
  if (sel) sel.value = code;
}

function buildSwitcher(lang) {
  const sel = document.getElementById("lang-switcher");
  if (!sel) return;
  sel.replaceChildren();
  LANGS.forEach((language) => {
    const option = document.createElement("option");
    option.value = language.code;
    option.textContent = language.native;
    sel.append(option);
  });
  sel.value = lang;
  sel.addEventListener("change", (e) => setLanguage(e.target.value));
}

// initI18n — call once after DOM is ready. Populates the switcher, applies the
// stored/detected language, and sets <html lang>/<html dir>.
export function initI18n() {
  const lang = currentLang();
  buildSwitcher(lang);
  applyTranslations(lang);
  return lang;
}
