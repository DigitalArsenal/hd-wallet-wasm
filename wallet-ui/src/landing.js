// The landing page bootstrap (wallet.spacedatanetwork.org): runs the in-page
// demo. init() injects the modals and wires #nav-login / #hero-login.
// createWalletUI() is the wallet-origin transaction app; it only serves
// /transaction/<id> requests and leaves these buttons dead on this page.
//
// The wallet refuses to run inside a frame. GitHub Pages cannot send
// X-Frame-Options or a frame-ancestors header, and a <meta> CSP cannot carry
// frame-ancestors, so a hostile page could otherwise frame the seed and
// password forms and overlay them (clickjacking). Framed, the page shows a
// notice and a link that opens it on its own, and no wallet code starts.
import { initI18n, applyTranslations } from './i18n.js';
import { init } from './app.js';

function isFramed() {
  try {
    return window.top !== window.self;
  } catch {
    // A cross-origin parent throws on access: that is a frame.
    return true;
  }
}

function refuseFramed() {
  const notice = document.createElement('p');
  notice.className = 'framed-notice';
  notice.setAttribute('role', 'alert');
  notice.textContent = 'This wallet does not run inside another site. ';
  const link = document.createElement('a');
  link.href = window.location.href;
  link.target = '_top';
  link.rel = 'noopener';
  link.textContent = 'Open it on its own page.';
  notice.append(link);
  document.body.replaceChildren(notice);
}

if (isFramed()) {
  refuseFramed();
} else {
  // Localize the static landing page immediately (top-10 language support).
  initI18n();
  // Re-apply after the wallet UI injects its modals so any late [data-i18n]
  // nodes on the page pick up the active language too.
  window.__hdApplyI18n = applyTranslations;
  const opts = {};
  if (typeof window.__sdnOnLogin === 'function') {
    opts.onLogin = window.__sdnOnLogin;
  }
  if (window.__sdnOpenAccountAfterLogin === false) {
    opts.openAccountAfterLogin = false;
  }
  // init() resolves to the host controls (openAccount / closeAccount /
  // openLogin / logout / destroy); hosts that set __sdnWalletReady get them.
  init(document.body, opts).then((controls) => {
    if (typeof window.__sdnWalletReady === 'function' && controls) {
      window.__sdnWalletReady(Object.freeze({
        openLogin: () => controls.openLogin(),
        openAccount: (section) => controls.openAccount(section),
        closeAccount: () => controls.closeAccount(),
        logout: () => controls.logout(),
        destroy: () => controls.destroy(),
      }));
    }
  });
}
