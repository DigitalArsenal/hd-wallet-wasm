// The standalone ACCOUNT VIEW.
//
// # Why this file exists
//
// hd-wallet-ui has always had the account screen the rest of the world wants —
// a bond value in the header, a tab strip, and a vCard identity editor with
// upload-or-camera photo capture (src/template.js). It was simply not
// REACHABLE: the markup lives inside the wallet app, and the only mount the
// package exported (mountWalletOriginApp) calls start(), which demands a
// /transaction/<64 hex> path. A consumer who wanted the account screen had to
// call minified internals — which is forking the package, not using it.
//
// So this is the export: the same grammar, none of the app.
//
// # What it is and is not
//
// It is DOM, not a framework, and it is deliberately UNSTYLED beyond class
// names. Every element carries the class names the wallet app's own stylesheet
// already targets (`modal-tabs`, `modal-tab`, `modal-tab-content`,
// `account-modal-header`, `ph-portfolio-value`, `identity-card`, `photo-*`),
// so a consumer who loads the package stylesheet gets the wallet look, and a
// consumer with their own theme scopes those same names and gets theirs. That
// is what "mountable by consumers with their own styles" has to mean: one
// grammar, two skins, no fork.
//
// It holds NO key material, performs NO derivation, and talks to NO network.
// The caller owns all of that and passes values in / receives edits out. That
// keeps the export on the near side of the wallet's security boundary: adding
// an account SCREEN must not add an account KEYSTORE.
//
// Every node is built with createElement and textContent. Markup-parsing sinks
// are banned in this file by policy (test/dom-security.test.mjs) — an account
// screen renders names, organizations and notes that other people typed.

/** The tab set the wallet app itself ships, in its own order and casing. */
export const DEFAULT_ACCOUNT_TABS = Object.freeze([
  Object.freeze({ id: 'identity', label: 'Identity' }),
  Object.freeze({ id: 'trust', label: 'Trust Map' }),
  Object.freeze({ id: 'messaging', label: 'Messaging' }),
  Object.freeze({ id: 'wallet', label: 'Wallet' }),
  Object.freeze({ id: 'manage', label: 'Manage' }),
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

/**
 * Builds the account view.
 *
 * @param {object} options
 * @param {Document} [options.document]
 * @param {string} [options.title]            display name in the header
 * @param {{value?: string, label?: string}} [options.bond]
 *        The BOND VALUE AT THE TOP. `value` is rendered verbatim — currency
 *        formatting is the caller's decision, not this component's, because the
 *        caller knows the locale and the asset.
 * @param {Array<{id: string, name: string}>} [options.wallets]
 * @param {string} [options.activeWalletId]
 * @param {(walletId: string) => void} [options.onWalletChange]
 * @param {Array<{label: string, tone?: string, title?: string}>} [options.chips]
 *        Header chips. Tone becomes a `chip-<tone>` class; this component does
 *        not decide what any tone MEANS.
 * @param {Array<{id: string, label: string, render?: (panel: HTMLElement) => void}>} [options.tabs]
 *        Defaults to DEFAULT_ACCOUNT_TABS. A consumer adds its own tabs here
 *        rather than forking: the strip is data, not markup.
 * @param {string} [options.activeTabId]
 * @param {(tabId: string) => void} [options.onTabChange]
 * @param {object} [options.identity]         the Identity tab's vCard editor
 * @param {Array<object>} [options.identity.fields]
 *        `{ id, label, value, readOnly, multiline, placeholder }`. A read-only
 *        field renders as a VALUE, never as a disabled input: a disabled box is
 *        a promise of an edit that is not coming.
 * @param {(values: Record<string, string>) => any} [options.identity.onSave]
 * @param {(blob: Blob) => any} [options.identity.onPhoto]
 * @param {() => any} [options.identity.onPhotoRemove]
 * @param {string} [options.identity.photoUrl]
 * @param {Array<{label: string, onClick: () => any, variant?: string}>} [options.actions]
 *        Header actions (sign out, and whatever else the host owns).
 * @param {() => void} [options.onClose]
 */
export function createAccountView(options = {}) {
  const doc = callerDocument(options);
  const tabs = (Array.isArray(options.tabs) && options.tabs.length ? options.tabs : DEFAULT_ACCOUNT_TABS)
    .filter((tab) => tab && typeof tab.id === 'string' && tab.id !== '');
  if (!tabs.length) throw new Error('createAccountView requires at least one tab');

  const root = el(doc, 'div', 'wallet-account-view modal-glass modal-wide');
  root.setAttribute('data-wallet-account-view', '');

  // ---- header: bond value at the top -------------------------------------
  const header = el(doc, 'div', 'modal-header account-modal-header');
  const info = el(doc, 'div', 'account-header-info');

  const walletRow = el(doc, 'div', 'account-wallet-row');
  const walletSelect = el(doc, 'select', 'glass-input compact account-wallet-select');
  walletSelect.setAttribute('aria-label', 'Select wallet');
  walletRow.append(walletSelect);

  const summary = el(doc, 'div', 'account-wallet-summary');
  const balanceLine = el(doc, 'div', 'account-wallet-balance-line');
  const bondValue = el(doc, 'div', 'ph-portfolio-value');
  bondValue.id = 'wallet-bond-value';
  const bondLabel = el(doc, 'div', 'ph-portfolio-label');
  balanceLine.append(bondValue, bondLabel);
  summary.append(balanceLine);

  const titleRow = el(doc, 'div', 'account-header-title');
  const titleText = el(doc, 'span', 'account-header-name');
  const chipRow = el(doc, 'span', 'account-header-chips');
  titleRow.append(titleText, chipRow);

  info.append(walletRow, summary, titleRow);

  const headerActions = el(doc, 'div', 'account-header-actions');
  const closeButton = button(doc, 'modal-close account-modal-close', '×', 'Close');
  closeButton.setAttribute('aria-label', 'Close');
  headerActions.append(closeButton);
  header.append(info, headerActions);

  // ---- tab strip ----------------------------------------------------------
  const tabStrip = el(doc, 'div', 'modal-tabs');
  tabStrip.setAttribute('role', 'tablist');
  const body = el(doc, 'div', 'modal-body');

  const panels = new Map();
  const buttons = new Map();
  for (const tab of tabs) {
    const tabButton = button(doc, 'modal-tab', asText(tab.label ?? tab.id));
    tabButton.dataset.modalTab = `${tab.id}-tab-content`;
    tabButton.setAttribute('role', 'tab');
    const panel = el(doc, 'div', 'modal-tab-content');
    panel.id = `${tab.id}-tab-content`;
    panel.setAttribute('role', 'tabpanel');
    buttons.set(tab.id, tabButton);
    panels.set(tab.id, panel);
    tabStrip.append(tabButton);
    body.append(panel);
  }

  root.append(header, tabStrip, body);

  let activeTabId = null;
  function setActiveTab(id) {
    if (!panels.has(id)) return;
    activeTabId = id;
    for (const [tabId, tabButton] of buttons) {
      const active = tabId === id;
      tabButton.classList.toggle('active', active);
      tabButton.setAttribute('aria-selected', active ? 'true' : 'false');
      panels.get(tabId).classList.toggle('active', active);
    }
    if (typeof options.onTabChange === 'function') options.onTabChange(id);
  }
  for (const [tabId, tabButton] of buttons) {
    tabButton.addEventListener('click', () => setActiveTab(tabId));
  }

  // ---- identity tab: editable vCard fields + photo ------------------------
  const identityPanel = panels.get('identity');
  const identity = createIdentitySection(doc, options.identity ?? {}, identityPanel);

  // Consumer-rendered panels. Identity is rendered here only when the caller
  // did not claim it themselves.
  for (const tab of tabs) {
    if (typeof tab.render === 'function') tab.render(panels.get(tab.id));
  }

  // ---- wiring -------------------------------------------------------------
  closeButton.addEventListener('click', () => {
    if (typeof options.onClose === 'function') options.onClose();
  });
  walletSelect.addEventListener('change', () => {
    if (typeof options.onWalletChange === 'function') options.onWalletChange(walletSelect.value);
  });

  function renderActions(actions) {
    for (const node of [...headerActions.querySelectorAll('.account-header-action')]) node.remove();
    for (const action of Array.isArray(actions) ? actions : []) {
      if (!action || typeof action.label !== 'string') continue;
      const node = button(
        doc,
        `glass-btn small account-header-action${action.variant ? ` ${action.variant}` : ''}`,
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

  function renderWallets(wallets, activeWalletId) {
    walletSelect.replaceChildren();
    const list = Array.isArray(wallets) ? wallets : [];
    for (const wallet of list) {
      if (!wallet || typeof wallet.id !== 'string') continue;
      const option = el(doc, 'option', '', asText(wallet.name ?? wallet.id));
      option.value = wallet.id;
      walletSelect.append(option);
    }
    walletSelect.hidden = list.length === 0;
    if (typeof activeWalletId === 'string' && list.some((w) => w?.id === activeWalletId)) {
      walletSelect.value = activeWalletId;
    }
  }

  /**
   * Applies a new state. Every key is optional; an absent key leaves what is on
   * screen alone, so a caller can push one changed field without re-supplying
   * a whole model (and without stomping an edit in progress).
   */
  function update(next = {}) {
    if ('title' in next) titleText.textContent = asText(next.title);
    if ('bond' in next) {
      bondValue.textContent = asText(next.bond?.value ?? '');
      bondLabel.textContent = asText(next.bond?.label ?? 'Bond');
    }
    if ('chips' in next) renderChips(next.chips);
    if ('actions' in next) renderActions(next.actions);
    if ('wallets' in next || 'activeWalletId' in next) {
      renderWallets(next.wallets ?? options.wallets, next.activeWalletId ?? options.activeWalletId);
    }
    if ('identity' in next) identity.update(next.identity ?? {});
    if ('activeTabId' in next) setActiveTab(next.activeTabId);
  }

  update({
    title: options.title ?? '',
    bond: options.bond ?? {},
    chips: options.chips,
    actions: options.actions,
    wallets: options.wallets,
    activeWalletId: options.activeWalletId,
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
  const card = el(doc, 'div', 'identity-card');

  // photo
  const photoWrap = el(doc, 'div', 'identity-card-photo');
  const preview = el(doc, 'div', 'photo-preview');
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
  const uploadButton = button(doc, 'glass-btn small', 'Upload');
  const cameraButton = button(doc, 'glass-btn small', 'Use Camera');
  const captureButton = button(doc, 'glass-btn small primary', 'Capture');
  const cancelButton = button(doc, 'glass-btn small', 'Cancel');
  const removeButton = button(doc, 'glass-btn small', 'Remove');
  captureButton.hidden = true;
  cancelButton.hidden = true;
  actions.append(uploadButton, cameraButton, captureButton, cancelButton, removeButton, fileInput);
  preview.append(image, video);
  const photoStatus = el(doc, 'p', 'photo-status');
  photoWrap.append(preview, actions, photoStatus);

  // fields
  const fieldList = el(doc, 'div', 'identity-fields');
  const saveRow = el(doc, 'div', 'identity-save-row');
  const saveButton = button(doc, 'glass-btn primary', 'Save');
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
        const input = el(doc, field.multiline ? 'textarea' : 'input', 'glass-input identity-field-input');
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
