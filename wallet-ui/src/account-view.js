/**
 * The account view shell: identity bar, section tabs and routing.
 *
 * The view is a full-width page panel under the SDN header (#account-view in
 * template.js), not a dialog. Exactly one section pane is visible at a time,
 * chosen by one function, showSection(id), which sets `hidden` on every other
 * pane and `aria-selected` on the tabs. Panes never reach into each other's
 * DOM; each owns its sub-views and resets them when a section is shown.
 *
 * Routing: `#account/<section>`. Opening sets the hash, switching sections
 * replaces it, Close clears it (and pops the history entry Open pushed, so one
 * Back afterwards leaves the page), and browser Back (a hash that is no longer
 * an account route) hides the view. While the view is open the landing page
 * behind it is `inert`; the SDN header and its mobile menu stay usable.
 * Close returns focus to the control that opened the view.
 */

// Body children that stay interactive while the view is open: the SDN chrome.
const CHROME_CLASSES = Object.freeze(['sdn-header', 'sdn-menu']);

const NON_TEXT_INPUTS = new Set(['button', 'checkbox', 'color', 'file', 'image', 'radio', 'range', 'reset', 'submit']);

/** True when a key event's target is a text field (Escape there is not "close"). */
function isTextEntry(target) {
  const tag = String(target?.tagName ?? '').toLowerCase();
  if (tag === 'textarea' || tag === 'select') return true;
  if (tag === 'input') return !NON_TEXT_INPUTS.has(String(target.type ?? 'text').toLowerCase());
  return target?.isContentEditable === true;
}

import { el, wireCopy } from './ui-dom.js';
import { readSection, writeSection } from './account-storage.js';
import { shortPeerId } from './identity-keys.js';

export const SECTIONS = Object.freeze(['profile', 'messages', 'people', 'assets', 'settings']);

export const SECTION_LABELS = Object.freeze({
  profile: 'Profile',
  messages: 'Messages',
  people: 'People',
  assets: 'Assets',
  settings: 'Settings',
});

const HASH_PREFIX = '#account/';

/** The section named by `#account/<section>`, or null. */
export function parseAccountHash(hash) {
  const value = String(hash ?? '');
  if (!value.startsWith(HASH_PREFIX)) return null;
  const section = value.slice(HASH_PREFIX.length).split(/[/?#]/u)[0].toLowerCase();
  return SECTIONS.includes(section) ? section : null;
}

export function isAccountHash(hash) {
  return String(hash ?? '').startsWith(HASH_PREFIX);
}

function sectionOrDefault(value) {
  return SECTIONS.includes(value) ? value : 'profile';
}

/**
 * @param {object} options
 * @param {Document} options.document
 * @param {Window} [options.window]
 * @param {HTMLElement} options.root          #account-view
 * @param {Record<string, {reset?: Function, show?: Function}>} [options.panes]
 * @param {() => void} [options.onClose]
 * @param {(section: string) => void} [options.onSection]
 * @param {() => boolean} [options.canOpen]   false while signed out
 * @param {Storage|null} [options.storage]
 */
export function createAccountShell({
  document: doc,
  window: win = doc.defaultView ?? globalThis.window,
  root,
  panes = {},
  onClose = () => {},
  onSection = () => {},
  canOpen = () => true,
  storage,
}) {
  const tabs = new Map();
  const panels = new Map();
  for (const section of SECTIONS) {
    const tab = root.querySelector(`#account-tab-${section}`);
    const panel = root.querySelector(`#account-pane-${section}`);
    if (!tab || !panel) throw new Error(`The account view template is missing ${section}`);
    tabs.set(section, tab);
    panels.set(section, panel);
  }
  const closeButton = root.querySelector('#account-close');
  const nameEl = root.querySelector('#account-name');
  const addNameButton = root.querySelector('#account-add-name');
  const peerEl = root.querySelector('#account-peer-id');
  const copyPeerButton = root.querySelector('#account-copy-peer');
  const statusEl = root.querySelector('#account-status');
  const avatarEl = root.querySelector('#account-avatar');

  let current = null;
  let open = false;
  let pushedEntry = false;
  let opener = null;
  let peerIdValue = '';
  const inerted = [];
  const listeners = [];

  function listen(target, type, handler) {
    target?.addEventListener?.(type, handler);
    listeners.push(() => target?.removeEventListener?.(type, handler));
  }

  function storageArg() {
    return storage === undefined ? undefined : storage;
  }

  function showSection(id, { focus = false, updateHash = true, intent = null, render = true } = {}) {
    const section = sectionOrDefault(id);
    for (const name of SECTIONS) {
      const active = name === section;
      panels.get(name).hidden = !active;
      const tab = tabs.get(name);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
    }
    const previous = current;
    current = section;
    if (!render) return section;
    for (const [name, pane] of Object.entries(panes)) {
      if (typeof pane?.reset === 'function' && (name !== section || previous !== section)) {
        try { pane.reset(); } catch { /* a pane's reset never blocks a switch */ }
      }
    }
    try { panes[section]?.show?.(intent); } catch { /* the pane renders its own errors */ }
    writeSection(section, storageArg());
    if (open && updateHash) setHash(section, { replace: true });
    // Focus goes to the pane title, unless the pane already put it on a
    // control of its own (Profile's edit mode focuses the Name input).
    const panel = panels.get(section);
    if (focus && !panel.contains(doc.activeElement)) {
      const title = panel.querySelector('.pane-title');
      try { title?.focus?.(); } catch { /* focus is best effort */ }
    }
    onSection(section);
    return section;
  }

  function setHash(section, { replace }) {
    const target = `${HASH_PREFIX}${section}`;
    const location = win?.location;
    if (!location || location.hash === target) return;
    const url = `${location.pathname ?? ''}${location.search ?? ''}${target}`;
    try {
      if (replace && typeof win.history?.replaceState === 'function') {
        win.history.replaceState(win.history.state ?? null, '', url);
      } else {
        location.hash = target;
        pushedEntry = true;
      }
    } catch {
      try { location.hash = target; } catch { /* an embedded host may forbid it */ }
    }
  }

  function clearHash() {
    const location = win?.location;
    const pushed = pushedEntry;
    pushedEntry = false;
    if (!location || !isAccountHash(location.hash)) return;
    const url = `${location.pathname ?? ''}${location.search ?? ''}`;
    try {
      win.history.replaceState(win.history.state ?? null, '', url || '.');
    } catch {
      try { location.hash = ''; } catch { /* nothing to clear */ }
      return;
    }
    // Open pushed an entry; with the hash cleared it is the same page as the
    // one before it, so step back over it. Back then leaves the page at once.
    if (pushed && typeof win.history?.back === 'function') {
      try { win.history.back(); } catch { /* history is the host's */ }
    }
  }

  function headerBottom() {
    try {
      const header = doc.querySelector('.sdn-header');
      const bottom = header?.getBoundingClientRect?.().bottom;
      return Number.isFinite(bottom) && bottom > 0 ? Math.round(bottom) : 0;
    } catch {
      return 0;
    }
  }

  function setInert(on) {
    if (on) {
      const body = doc.body;
      const children = body?.children ? [...body.children] : [];
      for (const child of children) {
        if (child === root || child.contains?.(root)) continue;
        if (CHROME_CLASSES.some((name) => child.classList?.contains?.(name))) continue;
        if (/^(SCRIPT|STYLE|LINK|TEMPLATE)$/iu.test(child.tagName ?? '')) continue;
        if (child.inert) continue;
        child.inert = true;
        inerted.push(child);
      }
    } else {
      while (inerted.length) {
        const child = inerted.pop();
        child.inert = false;
      }
    }
  }

  function openView(section, intent = null) {
    if (!canOpen()) return false;
    const target = sectionOrDefault(section ?? readSection(storageArg()));
    const top = headerBottom();
    try { root.style?.setProperty?.('--account-top', `${top}px`); } catch { /* default 0 */ }
    root.hidden = false;
    root.classList.add('is-open');
    if (!open) {
      open = true;
      const active = doc.activeElement;
      opener = active && active !== doc.body && !root.contains?.(active) ? active : null;
      setInert(true);
      const alreadyThere = parseAccountHash(win?.location?.hash) !== null;
      setHash(target, { replace: alreadyThere });
    }
    showSection(target, { focus: true, updateHash: true, intent });
    return true;
  }

  function closeView({ fromHash = false } = {}) {
    if (!open && root.hidden) return;
    open = false;
    root.hidden = true;
    root.classList.remove('is-open');
    setInert(false);
    for (const pane of Object.values(panes)) {
      try { pane?.reset?.(); } catch { /* best effort */ }
    }
    if (fromHash) pushedEntry = false;
    else clearHash();
    const returnTo = opener;
    opener = null;
    if (returnTo && returnTo.isConnected !== false && !returnTo.inert) {
      try { returnTo.focus?.(); } catch { /* the opener is gone */ }
    }
    onClose();
  }

  function handleHashChange() {
    const section = parseAccountHash(win?.location?.hash);
    if (section) {
      if (!open) {
        if (!openView(section)) clearHash();
      } else if (section !== current) {
        showSection(section, { updateHash: false });
      }
    } else if (open) {
      closeView({ fromHash: true });
    }
  }

  function setIdentity({ name = '', avatar = null, peerId = '', statusText = '', onAddName = null } = {}) {
    const hasName = String(name).trim() !== '';
    nameEl.textContent = hasName ? name : '';
    nameEl.hidden = !hasName;
    addNameButton.hidden = hasName || typeof onAddName !== 'function';
    addNameButton.onclick = typeof onAddName === 'function' ? () => onAddName() : null;
    peerIdValue = String(peerId ?? '');
    peerEl.textContent = shortPeerId(peerIdValue);
    peerEl.title = peerIdValue;
    copyPeerButton.hidden = peerIdValue === '';
    statusEl.textContent = statusText;
    renderAvatar(avatar, name);
  }

  function renderAvatar(avatar, name) {
    avatarEl.replaceChildren();
    avatarEl.className = 'account-avatar';
    if (avatar?.url) {
      const image = el(doc, 'img');
      image.alt = '';
      image.src = avatar.url;
      avatarEl.append(image);
      avatarEl.classList.add('has-photo');
      return;
    }
    const initials = avatar?.initials || '';
    if (initials) {
      avatarEl.append(el(doc, 'span', 'avatar-initials', initials));
      return;
    }
    avatarEl.classList.add('is-mark');
    avatarEl.append(el(doc, 'span', 'avatar-mark'));
    void name;
  }

  // ---- wiring ---------------------------------------------------------------
  for (const [section, tab] of tabs) {
    listen(tab, 'click', () => showSection(section, { focus: true }));
    listen(tab, 'keydown', (event) => {
      const index = SECTIONS.indexOf(section);
      let next = null;
      if (event.key === 'ArrowRight') next = SECTIONS[(index + 1) % SECTIONS.length];
      else if (event.key === 'ArrowLeft') next = SECTIONS[(index + SECTIONS.length - 1) % SECTIONS.length];
      else if (event.key === 'Home') next = SECTIONS[0];
      else if (event.key === 'End') next = SECTIONS[SECTIONS.length - 1];
      if (!next) return;
      event.preventDefault?.();
      tabs.get(next).focus?.();
    });
  }
  listen(closeButton, 'click', () => closeView());
  wireCopy(copyPeerButton, () => peerIdValue);
  listen(win, 'hashchange', handleHashChange);
  listen(doc, 'keydown', (event) => {
    if (event.key !== 'Escape' || !open || event.defaultPrevented) return;
    // A dialog layered above the view (the login window) handles its own Escape.
    if (doc.querySelector?.('.modal.active')) return;
    // Escape in a text field (a message being written, a profile being edited)
    // must not close the view and throw the text away.
    if (isTextEntry(event.target)) return;
    event.preventDefault?.();
    closeView();
  });

  root.hidden = true;
  showSection(sectionOrDefault(readSection(storageArg())), { updateHash: false, render: false });

  return Object.freeze({
    open: openView,
    close: closeView,
    showSection,
    handleHashChange,
    setIdentity,
    isOpen: () => open,
    currentSection: () => current,
    panel: (section) => panels.get(section) ?? null,
    tab: (section) => tabs.get(section) ?? null,
    destroy() {
      for (const remove of listeners.splice(0)) remove();
      setInert(false);
    },
  });
}
