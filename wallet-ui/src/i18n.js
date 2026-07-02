// Lightweight vanilla i18n runtime for the HD Wallet WASM site.
//
// Usage in HTML:
//   <h2 data-i18n="features.heading">Features</h2>          (textContent)
//   <p  data-i18n-html="adv.intro.desc">...<strong>..</strong></p>  (innerHTML, for strings with markup)
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

export function applyTranslations(lang = currentLang()) {
  const dict = LOCALES[lang] || LOCALES.en;
  const pick = (key) => dict[key] ?? LOCALES.en[key];

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const v = pick(el.getAttribute("data-i18n"));
    if (v != null) el.textContent = v;
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    const v = pick(el.getAttribute("data-i18n-html"));
    if (v != null) el.innerHTML = v;
  });
  document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
    el.getAttribute("data-i18n-attr")
      .split(",")
      .forEach((pair) => {
        const [attr, key] = pair.split(":").map((s) => s.trim());
        const v = pick(key);
        if (attr && v != null) el.setAttribute(attr, v);
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
  sel.innerHTML = LANGS.map(
    (l) => `<option value="${l.code}">${l.native}</option>`,
  ).join("");
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
