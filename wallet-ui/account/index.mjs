// The standalone ACCOUNT VIEW (hd-wallet-ui 3.0).
//
// # Why this file exists
//
// The wallet app's account screen is a page panel: an identity bar (avatar,
// name, short SDN peer ID with Copy, a quiet status word, Close), a row of
// section tabs and one visible section pane. Consumers who want that screen
// without the wallet app mount it from here: the same grammar, none of the app.
//
// # What it is and is not
//
// It is DOM, not a framework, and it is deliberately UNSTYLED beyond class
// names. Every element carries the class names the wallet app's own stylesheet
// (styles/account.css) targets — `account-identity-bar`, `account-tab`,
// `account-pane`, `btn`, `link-btn` — so a consumer who loads the package
// stylesheet gets the wallet look, and a consumer with their own theme scopes
// those same names and gets theirs.
//
// It holds NO key material, performs NO derivation, and talks to NO network.
// The caller owns all of that and passes values in / receives edits out. That
// keeps the export on the near side of the wallet's security boundary: adding
// an account SCREEN must not add an account KEYSTORE.
//
// Every node is built with createElement and textContent. Markup-parsing sinks
// are banned in this file by policy (test/dom-security.test.mjs) — an account
// screen renders names, organizations and notes that other people typed.

/** The section set the wallet app itself ships, in its own order and casing. */
export const DEFAULT_ACCOUNT_TABS = Object.freeze([
  Object.freeze({ id: 'profile', label: 'Profile' }),
  Object.freeze({ id: 'messages', label: 'Messages' }),
  Object.freeze({ id: 'people', label: 'People' }),
  Object.freeze({ id: 'assets', label: 'Assets' }),
  Object.freeze({ id: 'settings', label: 'Settings' }),
]);

/** Formats a browser can both capture and render. */
const PHOTO_TYPES = Object.freeze(['image/png', 'image/jpeg', 'image/webp']);

function el(document, tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined && text !== null && text !== '') node.textContent = String(text);
  return node;
}

function button(document, className, label, title) {
  const node = el(document, 'button', className, label);
  node.type = 'button';
  if (title) node.title = title;
  return node;
}

function asText(value) {
  return value === undefined || value === null ? '' : String(value);
}

function callerDocument(options) {
  if (options?.document) return options.document;
  if (typeof document !== 'undefined') return document;
  throw new Error('createAccountView requires a document');
}

/** `12D3KooW…x7Qp`: the first 8 characters, an ellipsis, the last 4. */
function shortPeerId(peerId) {
  const value = asText(peerId);
  return value.length <= 13 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function initialsOf(name) {
  const words = asText(name).trim().split(/\s+/u).filter(Boolean);
  if (words.length === 0) return '';
  const first = [...words[0]][0] ?? '';
  const last = words.length > 1 ? ([...words[words.length - 1]][0] ?? '') : '';
  return (first + last).toUpperCase();
}

/**
 * Builds the account view.
 *
 * @param {object} options
 * @param {Document} [options.document]
 * @param {string} [options.title]            the name in the identity bar
 * @param {string} [options.peerId]           the SDN peer ID; shown short, copied in full
 * @param {{url?: string, initials?: string}} [options.avatar]
 *        The identity-bar avatar: a photo URL the caller serves, or initials
 *        (derived from the title when absent).
 * @param {string} [options.status]           the quiet status word at the right
 * @param {Array<{label: string, tone?: string, title?: string}>} [options.chips]
 *        Small labels after the status. Tone becomes a `chip-<tone>` class;
 *        this component does not decide what any tone MEANS.
 * @param {Array<{id: string, label: string, render?: (panel: HTMLElement) => void}>} [options.tabs]
 *        Defaults to DEFAULT_ACCOUNT_TABS. A consumer adds its own sections here
 *        rather than forking: the strip is data, not markup.
 * @param {string} [options.activeTabId]
 * @param {(tabId: string) => void} [options.onTabChange]
 * @param {object} [options.identity]         the Profile section's field editor
 * @param {Array<object>} [options.identity.fields]
 *        `{ id, label, value, readOnly, multiline, placeholder }`. A read-only
 *        field renders as a VALUE, never as a disabled input: a disabled box is
 *        a promise of an edit that is not coming.
 * @param {(values: Record<string, string>) => any} [options.identity.onSave]
 * @param {(blob: Blob) => any} [options.identity.onPhoto]
 * @param {() => any} [options.identity.onPhotoRemove]
 * @param {string} [options.identity.photoUrl]
 * @param {Array<{label: string, onClick: () => any, variant?: string}>} [options.actions]
 *        Identity-bar actions (sign out, and whatever else the host owns).
 * @param {() => void} [options.onClose]
 */
export function createAccountView(options = {}) {
  const doc = callerDocument(options);
  const tabs = (Array.isArray(options.tabs) && options.tabs.length ? options.tabs : DEFAULT_ACCOUNT_TABS)
    .filter((tab) => tab && typeof tab.id === 'string' && tab.id !== '');
  if (!tabs.length) throw new Error('createAccountView requires at least one tab');

  const root = el(doc, 'div', 'wallet-account-view account-view');
  root.setAttribute('data-wallet-account-view', '');

  // ---- identity bar: avatar, name, short peer ID, status, close -------------
  const bar = el(doc, 'div', 'account-identity-bar');
  const inner = el(doc, 'div', 'account-identity-inner');
  const avatar = el(doc, 'div', 'account-avatar');
  avatar.setAttribute('aria-hidden', 'true');
  const text = el(doc, 'div', 'account-identity-text');
  const nameLine = el(doc, 'div', 'account-name-line');
  const titleText = el(doc, 'span', 'account-name account-header-name');
  nameLine.append(titleText);
  const peerLine = el(doc, 'div', 'account-peer-line');
  const peerText = el(doc, 'span', 'account-peer-id');
  const copyButton = button(doc, 'copy-chip', 'Copy');
  peerLine.append(peerText, copyButton);
  text.append(nameLine, peerLine);
  const statusText = el(doc, 'span', 'account-status');
  const chipRow = el(doc, 'span', 'account-header-chips');
  const headerActions = el(doc, 'div', 'account-header-actions');
  const closeButton = button(doc, 'btn btn-icon account-close', '×', 'Close');
  closeButton.setAttribute('aria-label', 'Close');
  headerActions.append(closeButton);
  inner.append(avatar, text, statusText, chipRow, headerActions);
  bar.append(inner);

  // ---- section tabs -----------------------------------------------------------
  const tabBar = el(doc, 'div', 'account-tabs');
  const tabStrip = el(doc, 'div', 'account-tabs-inner');
  tabStrip.setAttribute('role', 'tablist');
  tabBar.append(tabStrip);

  const panels = new Map();
  const buttons = new Map();
  const paneNodes = [];
  for (const tab of tabs) {
    const tabButton = button(doc, 'account-tab', asText(tab.label ?? tab.id));
    tabButton.dataset.section = tab.id;
    tabButton.id = `account-tab-${tab.id}`;
    tabButton.setAttribute('role', 'tab');
    tabButton.setAttribute('aria-controls', `account-pane-${tab.id}`);
    const panel = el(doc, 'section', 'account-pane');
    panel.id = `account-pane-${tab.id}`;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', `account-tab-${tab.id}`);
    buttons.set(tab.id, tabButton);
    panels.set(tab.id, panel);
    tabStrip.append(tabButton);
    paneNodes.push(panel);
  }

  root.append(bar, tabBar, ...paneNodes);

  let activeTabId = null;
  function setActiveTab(id) {
    if (!panels.has(id)) return;
    activeTabId = id;
    for (const [tabId, tabButton] of buttons) {
      const active = tabId === id;
      tabButton.setAttribute('aria-selected', active ? 'true' : 'false');
      tabButton.tabIndex = active ? 0 : -1;
      panels.get(tabId).hidden = !active;
    }
    if (typeof options.onTabChange === 'function') options.onTabChange(id);
  }
  const tabIds = [...buttons.keys()];
  for (const [tabId, tabButton] of buttons) {
    tabButton.addEventListener('click', () => setActiveTab(tabId));
    // Roving tabindex: the arrow keys, Home and End move focus along the tabs;
    // Enter and Space (the button's own click) activate.
    tabButton.addEventListener('keydown', (event) => {
      const index = tabIds.indexOf(tabId);
      let next = null;
      if (event.key === 'ArrowRight') next = tabIds[(index + 1) % tabIds.length];
      else if (event.key === 'ArrowLeft') next = tabIds[(index + tabIds.length - 1) % tabIds.length];
      else if (event.key === 'Home') next = tabIds[0];
      else if (event.key === 'End') next = tabIds[tabIds.length - 1];
      if (!next) return;
      event.preventDefault?.();
      buttons.get(next).focus?.();
    });
  }

  // ---- profile section: editable fields + photo -------------------------------
  const identityPanel = panels.get('profile') ?? panels.get('identity');
  const identity = createIdentitySection(doc, options.identity ?? {}, identityPanel);

  // Consumer-rendered panels.
  for (const tab of tabs) {
    if (typeof tab.render === 'function') tab.render(panels.get(tab.id));
  }

  // ---- wiring -------------------------------------------------------------
  let peerIdValue = '';
  closeButton.addEventListener('click', () => {
    if (typeof options.onClose === 'function') options.onClose();
  });
  copyButton.addEventListener('click', async () => {
    const clipboard = doc.defaultView?.navigator?.clipboard;
    if (!peerIdValue || typeof clipboard?.writeText !== 'function') return;
    try {
      await clipboard.writeText(peerIdValue);
      copyButton.textContent = 'Copied';
      const host = doc.defaultView ?? globalThis;
      host.setTimeout(() => { copyButton.textContent = 'Copy'; }, 1500);
    } catch {
      // Clipboard refused: the full value stays available as the title.
    }
  });

  function renderActions(actions) {
    for (const node of [...headerActions.querySelectorAll('.account-header-action')]) node.remove();
    for (const action of Array.isArray(actions) ? actions : []) {
      if (!action || typeof action.label !== 'string') continue;
      const node = button(
        doc,
        `btn btn-sm account-header-action${action.variant ? ` ${action.variant}` : ''}`,
        action.label,
        action.title,
      );
      node.addEventListener('click', () => {
        if (typeof action.onClick === 'function') action.onClick();
      });
      headerActions.insertBefore(node, closeButton);
    }
  }

  function renderChips(chips) {
    chipRow.replaceChildren();
    for (const chip of Array.isArray(chips) ? chips : []) {
      if (!chip || typeof chip.label !== 'string') continue;
      const node = el(doc, 'span', `account-chip${chip.tone ? ` chip-${chip.tone}` : ''}`, chip.label);
      if (chip.title) node.title = chip.title;
      chipRow.append(node);
    }
  }

  let titleValue = '';
  let avatarValue = null;
  function renderAvatar() {
    avatar.replaceChildren();
    avatar.className = 'account-avatar';
    const url = asText(avatarValue?.url);
    if (url) {
      const image = el(doc, 'img', 'account-avatar-image');
      image.alt = '';
      image.src = url;
      avatar.append(image);
      return;
    }
    const initials = asText(avatarValue?.initials) || initialsOf(titleValue);
    if (initials) avatar.append(el(doc, 'span', 'avatar-initials', initials));
    else {
      avatar.classList.add('is-mark');
      avatar.append(el(doc, 'span', 'avatar-mark'));
    }
  }

  /**
   * Applies a new state. Every key is optional; an absent key leaves what is on
   * screen alone, so a caller can push one changed field without re-supplying
   * a whole model (and without stomping an edit in progress).
   */
  function update(next = {}) {
    if ('title' in next) {
      titleValue = asText(next.title);
      titleText.textContent = titleValue;
      renderAvatar();
    }
    if ('avatar' in next) {
      avatarValue = next.avatar ?? null;
      renderAvatar();
    }
    if ('peerId' in next) {
      peerIdValue = asText(next.peerId);
      peerText.textContent = shortPeerId(peerIdValue);
      peerText.title = peerIdValue;
      copyButton.hidden = peerIdValue === '';
    }
    if ('status' in next) statusText.textContent = asText(next.status);
    if ('chips' in next) renderChips(next.chips);
    if ('actions' in next) renderActions(next.actions);
    if ('identity' in next) identity.update(next.identity ?? {});
    if ('activeTabId' in next) setActiveTab(next.activeTabId);
  }

  update({
    title: options.title ?? '',
    avatar: options.avatar ?? null,
    peerId: options.peerId ?? '',
    status: options.status ?? '',
    chips: options.chips,
    actions: options.actions,
  });
  setActiveTab(
    typeof options.activeTabId === 'string' && panels.has(options.activeTabId)
      ? options.activeTabId
      : tabs[0].id,
  );

  return {
    element: root,
    panel: (id) => panels.get(id) ?? null,
    getActiveTab: () => activeTabId,
    setActiveTab,
    update,
    destroy() {
      identity.destroy();
      root.remove();
    },
  };
}

/** Mounts the view into a container and returns the same handle. */
export function mountAccountView(container, options = {}) {
  if (!container || typeof container.append !== 'function') {
    throw new Error('mountAccountView requires a container element');
  }
  const view = createAccountView({ document: container.ownerDocument, ...options });
  container.append(view.element);
  return view;
}

// ---------------------------------------------------------------------------

function createIdentitySection(doc, config, panel) {
  const card = el(doc, 'div', 'pane identity-card');

  // photo
  const photoWrap = el(doc, 'div', 'identity-card-photo');
  const preview = el(doc, 'div', 'photo-circle photo-preview');
  const image = el(doc, 'img', 'photo-image');
  image.alt = '';
  image.hidden = true;
  const video = el(doc, 'video', 'photo-camera');
  video.autoplay = true;
  video.playsInline = true;
  video.hidden = true;
  const actions = el(doc, 'div', 'photo-actions');
  const fileInput = el(doc, 'input', 'photo-file-input');
  fileInput.type = 'file';
  fileInput.accept = PHOTO_TYPES.join(',');
  fileInput.hidden = true;
  const uploadButton = button(doc, 'link-btn', 'Upload photo');
  const cameraButton = button(doc, 'link-btn', 'Take photo');
  const captureButton = button(doc, 'btn btn-primary btn-sm', 'Capture');
  const cancelButton = button(doc, 'btn btn-sm', 'Cancel');
  const removeButton = button(doc, 'link-btn', 'Remove photo');
  captureButton.hidden = true;
  cancelButton.hidden = true;
  actions.append(uploadButton, cameraButton, captureButton, cancelButton, removeButton, fileInput);
  preview.append(image, video);
  const photoStatus = el(doc, 'p', 'photo-status');
  photoWrap.append(preview, actions, photoStatus);

  // fields
  const fieldList = el(doc, 'div', 'identity-fields');
  const saveRow = el(doc, 'div', 'identity-save-row');
  const saveButton = button(doc, 'btn btn-primary identity-save', 'Save');
  const saveStatus = el(doc, 'span', 'identity-save-status');
  saveRow.append(saveButton, saveStatus);

  card.append(photoWrap, fieldList, saveRow);
  if (panel) panel.append(card);

  const inputs = new Map();
  let stream = null;

  function stopCamera() {
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
      stream = null;
    }
    video.hidden = true;
    if ('srcObject' in video) video.srcObject = null;
    captureButton.hidden = true;
    cancelButton.hidden = true;
    cameraButton.hidden = false;
    uploadButton.hidden = false;
  }

  function renderFields(fields) {
    fieldList.replaceChildren();
    inputs.clear();
    let editable = false;
    for (const field of Array.isArray(fields) ? fields : []) {
      if (!field || typeof field.id !== 'string') continue;
      const row = el(doc, 'div', 'identity-field');
      const label = el(doc, 'label', 'identity-field-label', asText(field.label ?? field.id));
      row.append(label);
      if (field.readOnly) {
        // A read-only fact renders as a VALUE. Never a disabled input: a greyed
        // box says "you could edit this later", and for a fingerprint or a
        // pinned key that is simply untrue.
        const value = el(doc, 'div', 'identity-field-value', asText(field.value));
        if (field.title) value.title = field.title;
        row.append(value);
      } else {
        editable = true;
        const input = el(doc, field.multiline ? 'textarea' : 'input', `${field.multiline ? 'textarea' : 'input'} identity-field-input`);
        if (!field.multiline) input.type = 'text';
        input.value = asText(field.value);
        if (field.placeholder) input.placeholder = field.placeholder;
        const inputId = `identity-field-${field.id}`;
        input.id = inputId;
        label.setAttribute('for', inputId);
        inputs.set(field.id, input);
        row.append(input);
      }
      if (field.note) row.append(el(doc, 'p', 'identity-field-note', asText(field.note)));
      fieldList.append(row);
    }
    saveRow.hidden = !editable;
  }

  function setPhoto(url) {
    const value = asText(url);
    image.hidden = value === '';
    if (value) image.src = value;
    else image.removeAttribute('src');
    removeButton.hidden = value === '';
  }

  function setStatus(node, text, tone) {
    node.textContent = asText(text);
    node.className = node.className.split(' ').filter((c) => !c.startsWith('status-')).join(' ');
    if (tone) node.classList.add(`status-${tone}`);
  }

  async function deliverPhoto(blob) {
    if (typeof config.onPhoto !== 'function') return;
    setStatus(photoStatus, 'Pinning…', 'busy');
    try {
      await config.onPhoto(blob);
      setStatus(photoStatus, '', null);
    } catch (error) {
      setStatus(photoStatus, error?.message || 'The photo could not be stored.', 'error');
    }
  }

  uploadButton.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = '';
    if (file) void deliverPhoto(file);
  });

  cameraButton.addEventListener('click', async () => {
    const media = doc.defaultView?.navigator?.mediaDevices;
    if (!media || typeof media.getUserMedia !== 'function') {
      setStatus(photoStatus, 'This browser has no camera available.', 'error');
      return;
    }
    try {
      stream = await media.getUserMedia({ video: true });
    } catch {
      setStatus(photoStatus, 'Camera access was refused.', 'error');
      return;
    }
    if ('srcObject' in video) video.srcObject = stream;
    video.hidden = false;
    captureButton.hidden = false;
    cancelButton.hidden = false;
    cameraButton.hidden = true;
    uploadButton.hidden = true;
    setStatus(photoStatus, '', null);
  });

  cancelButton.addEventListener('click', stopCamera);

  captureButton.addEventListener('click', async () => {
    const canvas = doc.createElement('canvas');
    canvas.width = video.videoWidth || 512;
    canvas.height = video.videoHeight || 512;
    const context = typeof canvas.getContext === 'function' ? canvas.getContext('2d') : null;
    if (!context) {
      setStatus(photoStatus, 'This browser cannot capture from the camera.', 'error');
      return;
    }
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    stopCamera();
    const blob = await new Promise((resolveBlob) => {
      if (typeof canvas.toBlob === 'function') canvas.toBlob(resolveBlob, 'image/png');
      else resolveBlob(null);
    });
    if (blob) await deliverPhoto(blob);
    else setStatus(photoStatus, 'The capture produced no image.', 'error');
  });

  removeButton.addEventListener('click', async () => {
    if (typeof config.onPhotoRemove !== 'function') return;
    setStatus(photoStatus, 'Removing…', 'busy');
    try {
      await config.onPhotoRemove();
      setStatus(photoStatus, '', null);
    } catch (error) {
      setStatus(photoStatus, error?.message || 'The photo could not be removed.', 'error');
    }
  });

  saveButton.addEventListener('click', async () => {
    if (typeof config.onSave !== 'function') return;
    const values = {};
    for (const [id, input] of inputs) values[id] = input.value;
    saveButton.disabled = true;
    setStatus(saveStatus, 'Saving…', 'busy');
    try {
      await config.onSave(values);
      setStatus(saveStatus, 'Saved', 'ok');
    } catch (error) {
      setStatus(saveStatus, error?.message || 'The change could not be saved.', 'error');
    } finally {
      saveButton.disabled = false;
    }
  });

  renderFields(config.fields);
  setPhoto(config.photoUrl);

  return {
    update(next = {}) {
      if ('fields' in next) renderFields(next.fields);
      if ('photoUrl' in next) setPhoto(next.photoUrl);
      if ('photoStatus' in next) setStatus(photoStatus, next.photoStatus?.text, next.photoStatus?.tone);
      if ('saveStatus' in next) setStatus(saveStatus, next.saveStatus?.text, next.saveStatus?.tone);
      if (typeof next.onSave === 'function') config.onSave = next.onSave;
      if (typeof next.onPhoto === 'function') config.onPhoto = next.onPhoto;
      if (typeof next.onPhotoRemove === 'function') config.onPhotoRemove = next.onPhotoRemove;
    },
    destroy: stopCamera,
  };
}
