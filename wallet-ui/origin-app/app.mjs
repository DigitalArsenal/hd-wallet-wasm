import { WalletOriginController, WalletOriginError } from './controller.mjs';
import {
  APPROVAL_UNAVAILABLE,
  ApprovalConfigurationController,
  copyApprovalConfiguration,
  deriveExplicitLegacyIdentity,
  renderAccount,
  renderLegacyMigrationLauncher,
  renderQuarantinedWalletManager,
  renderRememberedWalletForget,
} from './account.mjs';
import { createSameOriginWalletRelay } from './relay.mjs';
import { resolveRegistryBinding } from './registry.mjs';

const TRANSACTION_PATH = /^\/transaction\/([0-9a-f]{64})$/u;
const encoder = new TextEncoder();
const intrinsicFill = Uint8Array.prototype.fill;
const defaultRegistry = Object.freeze({ resolveRegistryBinding });

function wipe(bytes) {
  if (!(bytes instanceof Uint8Array)) return;
  try { intrinsicFill.call(bytes, 0); } catch { /* detached credential bytes are unusable */ }
}

function isWellFormed(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(++index);
      if (!(second >= 0xdc00 && second <= 0xdfff)) return false;
    } else if (first >= 0xdc00 && first <= 0xdfff) return false;
  }
  return true;
}

function invalidTransaction() {
  return new WalletOriginError('INVALID_TRANSACTION');
}

function appendLabelledControl(document, form, labelText, control) {
  const label = document.createElement('label');
  const text = document.createElement('span');
  text.textContent = labelText;
  label.append(text, control);
  form.append(label);
}

function clearCredentialForm(form, controls) {
  for (const control of controls) {
    try { control.value = ''; } catch { /* continue */ }
    try { control.defaultValue = ''; } catch { /* continue */ }
    try { control.disabled = true; } catch { /* continue */ }
    try { control.inert = true; } catch { /* continue */ }
    try { control.removeAttribute?.('name'); } catch { /* continue */ }
    try { control.removeAttribute?.('autocomplete'); } catch { /* continue */ }
    try { control.setSelectionRange?.(0, 0); } catch { /* continue */ }
    try { control.setCustomValidity?.(''); } catch { /* continue */ }
  }
  try { form.remove?.(); } catch { /* fields were already cleared */ }
}

function installQuarantineManager({
  clipboard,
  controller,
  document,
  onChanged = () => {},
}) {
  if (!controller || typeof controller.listQuarantinedWalletRecords !== 'function') return null;
  const container = document.createElement('section');
  container.className = 'wallet-quarantine-manager';
  const controllerGeneration = controller.generation;
  let destroyed = false;
  let localGeneration = 0;
  let listeners = [];
  let rendered = null;

  const isCurrent = (expectedLocalGeneration = localGeneration) => !destroyed
    && expectedLocalGeneration === localGeneration
    && controller.isUiGenerationCurrent?.(controllerGeneration) === true;
  const setStatus = (message, expectedLocalGeneration = localGeneration) => {
    if (isCurrent(expectedLocalGeneration) && rendered?.status) {
      rendered.status.textContent = message;
    }
  };
  const clearRendered = () => {
    localGeneration += 1;
    for (const [node, type, listener] of listeners) {
      try { node.removeEventListener?.(type, listener); } catch { /* detached controls are inert */ }
    }
    listeners = [];
    for (const row of rendered?.rows ?? []) {
      try { row.confirmation.value = ''; } catch { /* continue */ }
      try { row.confirmation.defaultValue = ''; } catch { /* continue */ }
      try { row.confirmation.disabled = true; } catch { /* continue */ }
    }
    if (rendered?.status) rendered.status.textContent = '';
    rendered = null;
  };
  const bind = (node, type, listener) => {
    node.addEventListener?.(type, listener);
    listeners.push([node, type, listener]);
  };
  const refresh = () => {
    clearRendered();
    if (destroyed || controller.isUiGenerationCurrent?.(controllerGeneration) !== true) {
      container.replaceChildren();
      container.hidden = true;
      return false;
    }
    let entries;
    try { entries = controller.listQuarantinedWalletRecords(); } catch {
      entries = [];
    }
    if (!Array.isArray(entries) || entries.length === 0) {
      container.replaceChildren();
      container.hidden = true;
      return false;
    }
    container.hidden = false;
    rendered = renderQuarantinedWalletManager(container, entries, { document });
    const renderedGeneration = localGeneration;
    for (const row of rendered.rows) {
      const { entry } = row;
      const onExport = async (event) => {
        if (event?.isTrusted !== true || !isCurrent(renderedGeneration)) return;
        if (entry.exportable !== true) {
          setStatus('Quarantined record is too large to export.', renderedGeneration);
          return;
        }
        let raw;
        try {
          raw = controller.exportQuarantinedWalletRecord(entry.key);
          if (typeof clipboard?.writeText !== 'function') throw new Error('clipboard unavailable');
          await clipboard.writeText(raw);
          setStatus('Quarantined record exported to the clipboard.', renderedGeneration);
        } catch {
          setStatus('Quarantined record export failed.', renderedGeneration);
        } finally {
          raw = null;
        }
      };
      const onDelete = (event) => {
        if (event?.isTrusted !== true || !isCurrent(renderedGeneration)) return;
        try { row.confirmation.value = ''; } catch { /* continue */ }
        try { row.confirmation.defaultValue = ''; } catch { /* continue */ }
        row.confirmationGroup.hidden = false;
        setStatus(`Type ${entry.key} to confirm deletion.`, renderedGeneration);
        try { row.confirmation.focus?.(); } catch { /* focus is best effort */ }
      };
      const onCancel = (event) => {
        if (event?.isTrusted !== true || !isCurrent(renderedGeneration)) return;
        try { row.confirmation.value = ''; } catch { /* continue */ }
        try { row.confirmation.defaultValue = ''; } catch { /* continue */ }
        row.confirmationGroup.hidden = true;
        setStatus('', renderedGeneration);
      };
      const onConfirm = (event) => {
        if (event?.isTrusted !== true || !isCurrent(renderedGeneration)) return;
        const confirmation = row.confirmation.value;
        if (confirmation !== entry.key) {
          setStatus('Type the exact storage key to confirm deletion.', renderedGeneration);
          return;
        }
        try {
          controller.deleteQuarantinedWalletRecord(entry.key, confirmation);
        } catch {
          setStatus('Quarantined record deletion failed.', renderedGeneration);
          return;
        }
        try { row.confirmation.value = ''; } catch { /* continue */ }
        try { row.confirmation.defaultValue = ''; } catch { /* continue */ }
        refresh();
        if (!destroyed) onChanged();
      };
      bind(row.exportButton, 'click', onExport);
      bind(row.deleteButton, 'click', onDelete);
      bind(row.cancel, 'click', onCancel);
      bind(row.confirm, 'click', onConfirm);
    }
    return true;
  };

  const hasEntries = refresh();
  return Object.freeze({
    container,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      clearRendered();
      container.replaceChildren();
      container.remove?.();
    },
    hasEntries,
    refresh,
  });
}

export function createPasswordCredentialPrompt({
  clipboard = globalThis.navigator?.clipboard,
  controller = null,
  document,
  mount = null,
  offerRememberedUnlock = true,
  title = 'Sign in',
}) {
  const mountNode = mount ?? document?.body;
  if (!document?.createElement || !mountNode?.append) throw new WalletOriginError('DOM_UNAVAILABLE');
  const section = document.createElement('section');
  section.className = 'wallet-login';
  const heading = document.createElement('h1');
  heading.textContent = title;
  const account = document.createElement('p');
  account.textContent = 'Account 0';
  const form = document.createElement('form');
  form.noValidate = true;
  const usernameControl = document.createElement('input');
  usernameControl.type = 'text';
  usernameControl.name = 'username';
  usernameControl.autocomplete = 'username';
  usernameControl.required = true;
  const passwordControl = document.createElement('input');
  passwordControl.type = 'password';
  passwordControl.name = 'password';
  passwordControl.autocomplete = 'current-password';
  passwordControl.required = true;
  appendLabelledControl(document, form, 'Username', usernameControl);
  appendLabelledControl(document, form, 'Password', passwordControl);
  let rememberControl = null;
  if (controller && typeof controller === 'object') {
    rememberControl = document.createElement('input');
    rememberControl.type = 'checkbox';
    rememberControl.dataset.walletRemember = 'prf-only';
    rememberControl.checked = false;
    rememberControl.defaultChecked = false;
    let rememberSupported = false;
    try { rememberSupported = controller.supportsRememberedWallet?.() === true; } catch {
      rememberSupported = false;
    }
    rememberControl.disabled = !rememberSupported;
    appendLabelledControl(document, form, 'Remember on this device', rememberControl);
  }
  const rememberStatus = document.createElement('p');
  rememberStatus.dataset.walletRememberStatus = 'true';
  let refreshRememberedUnlock = () => {};
  const quarantineManager = installQuarantineManager({
    clipboard,
    controller,
    document,
    onChanged: () => refreshRememberedUnlock(),
  });
  const actions = document.createElement('div');
  actions.className = 'wallet-login-actions';
  let unlockRemembered = null;
  let restoreAvailable = false;
  try { restoreAvailable = controller?.canRestoreRememberedWallet?.() === true; } catch {
    restoreAvailable = false;
  }
  if (restoreAvailable && offerRememberedUnlock) {
    unlockRemembered = document.createElement('button');
    unlockRemembered.type = 'button';
    unlockRemembered.dataset.walletAction = 'unlock-remembered';
    unlockRemembered.textContent = 'Unlock remembered wallet';
  }
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.dataset.walletAction = 'login';
  submit.textContent = 'Login';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel-login';
  cancel.textContent = 'Cancel';
  if (unlockRemembered) actions.append(unlockRemembered);
  actions.append(submit, cancel);
  form.append(actions);
  section.append(heading, account);
  if (quarantineManager?.hasEntries) section.append(quarantineManager.container);
  section.append(form, rememberStatus);
  mountNode.append(section);
  controller?.registerCredentialControls?.({ passwordControl, usernameControl });

  let settled = false;
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const cleanupListeners = () => {
    form.removeEventListener?.('submit', onSubmit);
    cancel.removeEventListener?.('click', onCancel);
    unlockRemembered?.removeEventListener?.('click', onUnlockRemembered);
  };
  const clearSupplementalControls = () => {
    quarantineManager?.destroy?.();
    if (rememberControl) {
      try { rememberControl.checked = false; } catch { /* continue */ }
      try { rememberControl.defaultChecked = false; } catch { /* continue */ }
      try { rememberControl.disabled = true; } catch { /* continue */ }
    }
    rememberStatus.textContent = '';
  };
  const removePrompt = () => {
    cleanupListeners();
    clearCredentialForm(form, [usernameControl, passwordControl]);
    clearSupplementalControls();
    section.remove?.();
  };
  const rejectAndClear = (code) => {
    if (settled) return;
    settled = true;
    try { controller?.revokeNow?.(code); } catch { /* local form cleanup still runs */ }
    removePrompt();
    rejectPromise(new WalletOriginError(code));
  };
  const onSubmit = (event) => {
    event?.preventDefault?.();
    if (settled || event?.isTrusted !== true) return;
    settled = true;
    cleanupListeners();
    quarantineManager?.destroy?.();
    resolvePromise({ passwordControl, rememberControl, rememberStatus, usernameControl });
  };
  const onCancel = (event) => {
    if (event?.isTrusted !== true) return;
    rejectAndClear('USER_CANCELLED');
  };
  const onUnlockRemembered = (event) => {
    if (settled || event?.isTrusted !== true) return;
    settled = true;
    cleanupListeners();
    quarantineManager?.destroy?.();
    clearCredentialForm(form, [usernameControl, passwordControl]);
    resolvePromise({ remembered: true, rememberStatus });
  };
  refreshRememberedUnlock = () => {
    if (settled || !offerRememberedUnlock) return;
    let available = false;
    try { available = controller?.canRestoreRememberedWallet?.() === true; } catch {
      available = false;
    }
    if (available && !unlockRemembered) {
      unlockRemembered = document.createElement('button');
      unlockRemembered.type = 'button';
      unlockRemembered.dataset.walletAction = 'unlock-remembered';
      unlockRemembered.textContent = 'Unlock remembered wallet';
      actions.replaceChildren(unlockRemembered, submit, cancel);
      unlockRemembered.addEventListener?.('click', onUnlockRemembered);
    } else if (!available && unlockRemembered) {
      unlockRemembered.removeEventListener?.('click', onUnlockRemembered);
      unlockRemembered.remove?.();
      unlockRemembered = null;
    }
  };
  form.addEventListener('submit', onSubmit);
  cancel.addEventListener('click', onCancel);
  unlockRemembered?.addEventListener?.('click', onUnlockRemembered);
  try { usernameControl.focus?.(); } catch { /* focus is best effort */ }
  return Object.freeze({
    cancel() {
      if (!settled) rejectAndClear('STALE_CONTROLLER');
      else removePrompt();
    },
    controls: Object.freeze({ passwordControl, rememberControl, rememberStatus, usernameControl }),
    form,
    promise,
    remove: removePrompt,
  });
}

function createMnemonicCredentialPrompt({
  document,
  mount = null,
  submitLabel = 'Compare legacy account',
  title = 'Enter the legacy BIP-39 mnemonic',
}) {
  const mountNode = mount ?? document?.body;
  if (!document?.createElement || !mountNode?.append) throw new WalletOriginError('DOM_UNAVAILABLE');
  const section = document.createElement('section');
  section.className = 'wallet-login wallet-legacy-credentials';
  const heading = document.createElement('h1');
  heading.textContent = title;
  const form = document.createElement('form');
  form.noValidate = true;
  const mnemonicControl = document.createElement('textarea');
  mnemonicControl.name = 'mnemonic';
  mnemonicControl.autocomplete = 'off';
  mnemonicControl.required = true;
  appendLabelledControl(document, form, 'Mnemonic', mnemonicControl);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.dataset.walletAction = 'confirm-legacy-mnemonic';
  submit.textContent = submitLabel;
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel-legacy-migration';
  cancel.textContent = 'Cancel';
  form.append(submit, cancel);
  section.append(heading, form);
  mountNode.append(section);
  let settled = false;
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const cleanupListeners = () => {
    form.removeEventListener?.('submit', onSubmit);
    cancel.removeEventListener?.('click', onCancel);
  };
  const removePrompt = () => {
    cleanupListeners();
    clearCredentialForm(form, [mnemonicControl]);
    section.remove?.();
  };
  const rejectAndClear = () => {
    if (settled) return;
    settled = true;
    removePrompt();
    rejectPromise(new WalletOriginError('USER_CANCELLED'));
  };
  const onSubmit = (event) => {
    event?.preventDefault?.();
    if (settled || event?.isTrusted !== true) return;
    settled = true;
    cleanupListeners();
    resolvePromise({ form, mnemonicControl, section });
  };
  const onCancel = (event) => {
    if (event?.isTrusted === true) rejectAndClear();
  };
  form.addEventListener('submit', onSubmit);
  cancel.addEventListener('click', onCancel);
  try { mnemonicControl.focus?.(); } catch { /* focus is best effort */ }
  return Object.freeze({
    cancel() {
      if (!settled) rejectAndClear();
      else removePrompt();
    },
    promise,
    remove: removePrompt,
  });
}

function createLegacyProfilePrompt({ document, mount = null, title = 'Choose legacy wallet profile' }) {
  const mountNode = mount ?? document?.body;
  if (!document?.createElement || !mountNode?.append) throw new WalletOriginError('DOM_UNAVAILABLE');
  const section = document.createElement('section');
  section.className = 'wallet-login wallet-legacy-profile';
  const heading = document.createElement('h1');
  heading.textContent = title;
  const explanation = document.createElement('p');
  explanation.textContent = 'Raw-v1 compatibility login requires the exact legacy profile. It cannot approve assets.';
  const form = document.createElement('form');
  form.noValidate = true;
  const select = document.createElement('select');
  select.dataset.walletLegacyProfile = 'required';
  select.required = true;
  select.value = '';
  for (const [value, label] of [
    ['', 'Select a legacy profile'],
    ['password-fast-v1-legacy', 'Legacy fast-password profile'],
    ['bip39-mnemonic-v1-legacy', 'Legacy BIP-39 mnemonic import'],
  ]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    if (value === '') {
      option.disabled = true;
      option.selected = true;
    }
    select.append(option);
  }
  appendLabelledControl(document, form, 'Legacy profile', select);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.dataset.walletAction = 'continue-legacy-login';
  submit.textContent = 'Continue';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel-legacy-login';
  cancel.textContent = 'Cancel';
  form.append(submit, cancel);
  section.append(heading, explanation, form);
  mountNode.append(section);
  let settled = false;
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const cleanupListeners = () => {
    form.removeEventListener?.('submit', onSubmit);
    cancel.removeEventListener?.('click', onCancel);
  };
  const clear = () => {
    try { select.value = ''; } catch { /* continue */ }
    clearCredentialForm(form, [select]);
    section.remove?.();
  };
  const rejectAndClear = () => {
    if (settled) return;
    settled = true;
    cleanupListeners();
    clear();
    rejectPromise(new WalletOriginError('USER_CANCELLED'));
  };
  const onSubmit = (event) => {
    event?.preventDefault?.();
    if (settled || event?.isTrusted !== true) return;
    const profile = select.value;
    if (profile !== 'password-fast-v1-legacy'
        && profile !== 'bip39-mnemonic-v1-legacy') return;
    settled = true;
    cleanupListeners();
    clear();
    resolvePromise(profile);
  };
  const onCancel = (event) => {
    if (event?.isTrusted === true) rejectAndClear();
  };
  form.addEventListener('submit', onSubmit);
  cancel.addEventListener('click', onCancel);
  try { select.focus?.(); } catch { /* focus is best effort */ }
  return Object.freeze({ cancel: rejectAndClear, promise });
}

function appendComparisonValue(document, container, label, value) {
  const row = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = `${label}: `;
  const text = document.createElement('span');
  text.textContent = String(value ?? '');
  row.append(strong, text);
  container.append(row);
}

function renderCompletion(document, windowObject, message, mount = null) {
  const mountNode = mount ?? document?.body;
  const section = document.createElement('section');
  section.className = 'wallet-complete';
  const heading = document.createElement('h1');
  heading.textContent = 'Complete';
  const detail = document.createElement('p');
  detail.textContent = message;
  const close = document.createElement('button');
  close.type = 'button';
  close.dataset.walletAction = 'close';
  close.textContent = 'Close';
  close.addEventListener('click', (event) => {
    if (event?.isTrusted !== true) return;
    try { windowObject?.close?.(); } catch { /* the user can close the popup */ }
  });
  section.append(heading, detail, close);
  mountNode?.replaceChildren?.(section);
}

function renderFailure(
  document,
  message = 'The wallet request could not be completed. Close this window.',
  mount = null,
) {
  const mountNode = mount ?? document?.body;
  if (!document?.createElement || !mountNode?.replaceChildren) return;
  const section = document.createElement('section');
  section.className = 'wallet-terminal-error';
  const heading = document.createElement('h1');
  heading.textContent = 'Wallet request stopped';
  const detail = document.createElement('p');
  detail.textContent = message;
  section.append(heading, detail);
  mountNode.replaceChildren(section);
}

function installAccountSurface({
  clipboard,
  controller,
  document,
  identity,
  isAppCurrent = () => true,
  makeCredentialPrompt,
  mount,
  onClear,
  wasm,
}) {
  const section = document.createElement('section');
  section.className = 'wallet-account';
  const accountView = document.createElement('div');
  const rendered = renderAccount(accountView, identity, { document });
  const approvalCard = document.createElement('section');
  approvalCard.className = 'wallet-approval-card';
  const approvalHeading = document.createElement('h2');
  approvalHeading.textContent = 'Asset review approval';
  const approvalStatus = document.createElement('p');
  const approvalOutput = document.createElement('div');
  const copy = document.createElement('button');
  copy.type = 'button';
  copy.dataset.walletAction = 'copy-approval';
  copy.textContent = 'Copy approval configuration';
  copy.disabled = !rendered.approvalAvailable;
  if (!rendered.approvalAvailable) approvalStatus.textContent = APPROVAL_UNAVAILABLE;
  approvalCard.append(approvalHeading, approvalStatus, copy, approvalOutput);

  const logout = document.createElement('button');
  logout.type = 'button';
  logout.dataset.walletAction = 'logout';
  logout.textContent = 'Logout';
  const returnToSite = document.createElement('button');
  returnToSite.type = 'button';
  returnToSite.dataset.walletAction = 'return-to-site';
  returnToSite.textContent = 'Return to site';
  const migration = document.createElement('section');
  migration.className = 'wallet-legacy-migration';
  const legacyLauncher = renderLegacyMigrationLauncher(migration, { document });
  let forgetAvailable = false;
  try { forgetAvailable = controller.canForgetRememberedWallet?.() === true; } catch {
    forgetAvailable = false;
  }
  const rememberedWallet = forgetAvailable ? document.createElement('section') : null;
  const forgetControls = rememberedWallet
    ? renderRememberedWalletForget(rememberedWallet, { document })
    : null;
  if (forgetControls) {
    forgetControls.launch.dataset.walletAction = 'forget-stored-wallet';
  }
  const quarantineManager = installQuarantineManager({
    clipboard,
    controller,
    document,
  });
  const exitStatus = document.createElement('p');
  exitStatus.className = 'wallet-account-exit-status';
  section.append(accountView, approvalCard);
  if (rememberedWallet) section.append(rememberedWallet);
  if (quarantineManager?.hasEntries) section.append(quarantineManager.container);
  section.append(returnToSite, logout, migration);
  mount.replaceChildren(section);

  const approval = new ApprovalConfigurationController({
    credentialRound: async (round) => {
      const prompt = makeCredentialPrompt({
        controller: null,
        document,
        mount,
        title: `Confirm account (${round} of 2)`,
      });
      if (prompt?.promise) pendingPrompts.add(prompt);
      try {
        return prompt?.promise ? await prompt.promise : await prompt;
      } finally {
        if (prompt?.promise) pendingPrompts.delete(prompt);
      }
    },
    expectedIdentity: identity,
    wasm,
  });
  const pendingPrompts = new Set();
  const legacyHandles = new Set();
  const destroyingLegacyHandles = new Set();
  const secretBuffers = new Set();
  let copying = false;
  let destroyed = false;
  let finishing = false;
  let completionPromise = null;
  let forgetting = false;
  let forgotten = false;
  let migrationRunning = false;
  let migrationInFlight = 0;
  let surfaceRemoved = false;
  let surfaceGeneration = 0;
  const isCurrent = (generation) => !destroyed && surfaceGeneration === generation;
  const assertCurrent = (generation) => {
    if (!isCurrent(generation)) throw new Error('account surface closed');
  };
  const ownSecretBuffer = (bytes) => {
    if (bytes instanceof Uint8Array) secretBuffers.add(bytes);
    return bytes;
  };
  const releaseSecretBuffer = (bytes) => {
    wipe(bytes);
    secretBuffers.delete(bytes);
  };
  const clearSecretBuffers = () => {
    const buffers = [...secretBuffers];
    secretBuffers.clear();
    for (const bytes of buffers) wipe(bytes);
  };
  const setSensitiveWorkBusy = () => {
    const busy = copying || migrationRunning || forgetting;
    returnToSite.disabled = finishing;
    logout.disabled = finishing;
    if (!destroyed) {
      copy.disabled = busy || !rendered.approvalAvailable;
      legacyLauncher.launch.disabled = busy;
      if (forgetControls) {
        forgetControls.launch.disabled = busy || forgotten;
        forgetControls.confirm.disabled = busy;
        forgetControls.cancel.disabled = busy;
      }
    }
  };
  const destroyLegacyHandle = (handle) => {
    if (!legacyHandles.has(handle)) return true;
    if (destroyingLegacyHandles.has(handle)) return false;
    destroyingLegacyHandles.add(handle);
    try {
      (wasm?.sdn ?? wasm).destroySdnIdentity(handle);
      legacyHandles.delete(handle);
      return true;
    } catch {
      return false;
    } finally {
      destroyingLegacyHandles.delete(handle);
    }
  };
  const cleanupLegacyHandles = () => {
    for (const handle of [...legacyHandles]) destroyLegacyHandle(handle);
    return legacyHandles.size === 0;
  };
  const onCopy = async (event) => {
    if (event?.isTrusted !== true || copying || migrationRunning || forgetting) return;
    const generation = surfaceGeneration;
    copying = true;
    setSensitiveWorkBusy();
    approvalStatus.textContent = 'Confirm the same account twice to enable Copy.';
    try {
      const configuration = await approval.confirm();
      assertCurrent(generation);
      const copied = await copyApprovalConfiguration(configuration, {
        assertCurrent: () => assertCurrent(generation),
        clipboard,
        container: approvalOutput,
        document,
      });
      assertCurrent(generation);
      approvalStatus.textContent = copied
        ? 'Approval configuration copied.'
        : 'Clipboard unavailable. Copy the exact configuration shown below.';
    } catch {
      if (isCurrent(generation)) {
        approvalStatus.textContent = 'The two entries did not produce the same account.';
      }
    } finally {
      copying = false;
      if (isCurrent(generation)) setSensitiveWorkBusy();
    }
  };
  const onLegacyLaunch = async (event) => {
    if (event?.isTrusted !== true || migrationRunning || copying || forgetting) return;
    const profile = legacyLauncher.select.value || 'password-fast-v1-legacy';
    if (profile !== 'password-fast-v1-legacy' && profile !== 'bip39-mnemonic-v1-legacy') {
      legacyLauncher.result.textContent = 'Legacy profile unavailable.';
      return;
    }
    const generation = surfaceGeneration;
    migrationRunning = true;
    migrationInFlight += 1;
    setSensitiveWorkBusy();
    legacyLauncher.result.textContent = 'Enter the selected legacy credentials to compare accounts.';
    let prompt = null;
    let usernameUtf8;
    let passwordUtf8;
    let mnemonicUtf8;
    let legacy = null;
    try {
      let credentials;
      if (profile === 'password-fast-v1-legacy') {
        prompt = makeCredentialPrompt({
          controller: null,
          document,
          mount,
          title: 'Enter the legacy fast-password account',
        });
        if (prompt?.promise) pendingPrompts.add(prompt);
        const controls = prompt?.promise ? await prompt.promise : await prompt;
        assertCurrent(generation);
        const username = controls?.usernameControl?.value;
        const password = controls?.passwordControl?.value;
        if (!isWellFormed(username) || !isWellFormed(password)) throw new Error('invalid legacy credentials');
        usernameUtf8 = ownSecretBuffer(encoder.encode(username));
        passwordUtf8 = ownSecretBuffer(encoder.encode(password));
        const form = controls?.usernameControl?.form ?? controls?.passwordControl?.form ?? prompt?.form;
        const formContainer = form?.parentNode;
        clearCredentialForm(form, [controls?.usernameControl, controls?.passwordControl]);
        formContainer?.remove?.();
        credentials = { passwordUtf8, usernameUtf8 };
      } else {
        prompt = createMnemonicCredentialPrompt({ document, mount });
        pendingPrompts.add(prompt);
        const controls = await prompt.promise;
        assertCurrent(generation);
        const mnemonic = controls?.mnemonicControl?.value;
        if (!isWellFormed(mnemonic)) throw new Error('invalid legacy credentials');
        mnemonicUtf8 = ownSecretBuffer(encoder.encode(mnemonic));
        clearCredentialForm(controls.form, [controls.mnemonicControl]);
        controls.section?.remove?.();
        credentials = { mnemonicUtf8 };
      }
      if (prompt?.promise) pendingPrompts.delete(prompt);
      legacy = await deriveExplicitLegacyIdentity({
        accountIndex: 0,
        credentials,
        operation: 'sdn.auth.raw-challenge.v1',
        profile,
        wasm,
        assertCurrent: () => assertCurrent(generation),
        ownHandle: (handle) => legacyHandles.add(handle),
      });
      assertCurrent(generation);
      if (!legacy?.handle) throw new Error('legacy derivation failed');
      const expectedScheme = profile === 'password-fast-v1-legacy'
        ? 'sdn-fast-password-auth-v1-legacy'
        : 'sdn-bip39-auth-v1-legacy';
      const authKey = Array.isArray(legacy.identity?.keys)
        ? legacy.identity.keys.find((key) => key?.purpose === 'sdn-authentication')
        : null;
      if (legacy.identity?.identityScheme !== expectedScheme
          || legacy.identity?.seedProfile !== profile
          || typeof legacy.identity?.accountXpub !== 'string'
          || !authKey || typeof authKey.publicKeyHex !== 'string'
          || !/^[0-9a-f]{64}$/u.test(authKey.publicKeyHex)) {
        throw new Error('legacy identity invalid');
      }
      const legacyIdentity = legacy.identity;
      if (!destroyLegacyHandle(legacy.handle)) throw new Error('legacy destruction failed');
      legacy = null;
      assertCurrent(generation);
      const modernAuth = identity.keys.find((key) => key.purpose === 'sdn-authentication');
      legacyLauncher.result.replaceChildren();
      appendComparisonValue(document, legacyLauncher.result, 'Current account xpub', identity.accountXpub);
      appendComparisonValue(document, legacyLauncher.result, 'Legacy account xpub', legacyIdentity.accountXpub);
      appendComparisonValue(document, legacyLauncher.result, 'Current authentication key', modernAuth?.publicKeyHex);
      appendComparisonValue(document, legacyLauncher.result, 'Legacy authentication key', authKey.publicKeyHex);
    } catch {
      if (isCurrent(generation)) {
        legacyLauncher.result.textContent = 'Legacy account comparison could not be completed.';
      }
    } finally {
      if (legacy?.handle) destroyLegacyHandle(legacy.handle);
      if (prompt?.promise) pendingPrompts.delete(prompt);
      releaseSecretBuffer(usernameUtf8);
      releaseSecretBuffer(passwordUtf8);
      releaseSecretBuffer(mnemonicUtf8);
      cleanupLegacyHandles();
      migrationInFlight -= 1;
      migrationRunning = false;
      if (isCurrent(generation)) setSensitiveWorkBusy();
    }
  };
  const clearForgetConfirmation = () => {
    if (!forgetControls) return;
    try { forgetControls.confirmation.value = ''; } catch { /* continue */ }
    try { forgetControls.confirmation.defaultValue = ''; } catch { /* continue */ }
  };
  const onForgetLaunch = (event) => {
    if (!forgetControls || event?.isTrusted !== true || copying || migrationRunning
        || forgetting || forgotten || destroyed) return;
    clearForgetConfirmation();
    forgetControls.confirmationGroup.hidden = false;
    forgetControls.status.textContent = `Type ${forgetControls.confirmationKey} to confirm.`;
    try { forgetControls.confirmation.focus?.(); } catch { /* focus is best effort */ }
  };
  const onForgetCancel = (event) => {
    if (!forgetControls || event?.isTrusted !== true || forgetting || destroyed) return;
    clearForgetConfirmation();
    forgetControls.confirmationGroup.hidden = true;
    forgetControls.status.textContent = 'Forget cancelled.';
  };
  const onForgetConfirm = (event) => {
    if (!forgetControls || event?.isTrusted !== true || copying || migrationRunning
        || forgetting || forgotten || destroyed) return;
    const confirmation = forgetControls.confirmation.value;
    if (confirmation !== forgetControls.confirmationKey) {
      forgetControls.status.textContent = 'Type the exact storage key to confirm.';
      return;
    }
    forgetting = true;
    setSensitiveWorkBusy();
    clearForgetConfirmation();
    try {
      controller.forgetRememberedWallet(confirmation);
      forgotten = true;
      forgetControls.confirmationGroup.hidden = true;
      forgetControls.status.textContent = 'Stored wallet forgotten. This account remains signed in.';
    } catch {
      forgetControls.status.textContent = 'Stored wallet could not be forgotten.';
    } finally {
      forgetting = false;
      if (!destroyed) setSensitiveWorkBusy();
    }
  };
  const terminalizeSurface = (retainExitSurface) => {
    if (!destroyed) {
      destroyed = true;
      surfaceGeneration += 1;
      copy.disabled = true;
      legacyLauncher.launch.disabled = true;
      if (forgetControls) {
        forgetControls.launch.disabled = true;
        forgetControls.confirm.disabled = true;
        forgetControls.cancel.disabled = true;
        clearForgetConfirmation();
        forgetControls.launch.removeEventListener?.('click', onForgetLaunch);
        forgetControls.confirm.removeEventListener?.('click', onForgetConfirm);
        forgetControls.cancel.removeEventListener?.('click', onForgetCancel);
      }
      quarantineManager?.destroy?.();
      clearSecretBuffers();
      copy.removeEventListener?.('click', onCopy);
      legacyLauncher.launch.removeEventListener?.('click', onLegacyLaunch);
      for (const prompt of pendingPrompts) prompt.cancel?.();
      pendingPrompts.clear();
    } else {
      clearSecretBuffers();
    }
    if (retainExitSurface && !surfaceRemoved) {
      exitStatus.textContent = 'Secure cleanup is still pending. Retry Return or Logout.';
      section.replaceChildren(exitStatus, returnToSite, logout);
      returnToSite.disabled = false;
      logout.disabled = false;
    }
  };
  const cleanupAuxiliaryOwners = () => {
    const approvalClean = approval.destroy();
    const legacyClean = cleanupLegacyHandles();
    return approvalClean && legacyClean && migrationInFlight === 0
      && !migrationRunning && !copying;
  };
  const destroySurface = () => {
    terminalizeSurface(false);
    if (!surfaceRemoved) {
      surfaceRemoved = true;
      returnToSite.disabled = true;
      logout.disabled = true;
      returnToSite.removeEventListener?.('click', onReturn);
      logout.removeEventListener?.('click', onLogout);
      section.remove?.();
    }
    return cleanupAuxiliaryOwners();
  };
  const finishAccount = (event, action, message, { requireTrustedEvent = true } = {}) => {
    if (requireTrustedEvent && event?.isTrusted !== true) return Promise.resolve();
    if (completionPromise) return completionPromise;
    if (finishing || surfaceRemoved) {
      return Promise.reject(new WalletOriginError('STALE_CONTROLLER'));
    }
    terminalizeSurface(true);
    if (!cleanupAuxiliaryOwners()) {
      exitStatus.textContent = 'Secure cleanup is still pending. Retry Return or Logout.';
      returnToSite.disabled = false;
      logout.disabled = false;
      return Promise.reject(new WalletOriginError('DESTRUCTION_FAILED'));
    }
    finishing = true;
    returnToSite.disabled = true;
    logout.disabled = true;
    completionPromise = (async () => {
      onClear();
      renderCompletion(document, null, message, mount);
      try {
        const result = await action();
        if (!isAppCurrent()) throw new WalletOriginError('STALE_CONTROLLER');
        return result;
      } catch (error) {
        if (isAppCurrent()) renderFailure(document, undefined, mount);
        throw error;
      }
    })();
    return completionPromise;
  };
  const onReturn = (event) => {
    void finishAccount(
      event,
      () => controller.returnToSite(),
      'Returning to the requesting site.',
    ).catch(() => {});
  };
  const onLogout = (event) => {
    void finishAccount(
      event,
      () => controller.logout(),
      'Logged out. Returning to the requesting site.',
    ).catch(() => {});
  };
  copy.addEventListener('click', onCopy);
  legacyLauncher.launch.addEventListener('click', onLegacyLaunch);
  forgetControls?.launch.addEventListener?.('click', onForgetLaunch);
  forgetControls?.confirm.addEventListener?.('click', onForgetConfirm);
  forgetControls?.cancel.addEventListener?.('click', onForgetCancel);
  returnToSite.addEventListener('click', onReturn);
  logout.addEventListener('click', onLogout);
  return Object.freeze({
    destroy: destroySurface,
    logout: () => finishAccount(
      null,
      () => controller.logout(),
      'Logged out. Returning to the requesting site.',
      { requireTrustedEvent: false },
    ),
  });
}

export function transactionIdFromLocation(location) {
  const pathname = location?.pathname;
  const search = location?.search ?? '';
  const hash = location?.hash ?? '';
  if (typeof pathname !== 'string' || search !== '' || hash !== '') throw invalidTransaction();
  const match = TRANSACTION_PATH.exec(pathname);
  if (!match) throw invalidTransaction();
  return match[1];
}

export function createWalletOriginApp(configuration) {
  const windowObject = configuration?.window ?? globalThis.window;
  const documentObject = configuration?.document ?? windowObject?.document ?? globalThis.document;
  const mount = configuration?.mount ?? documentObject?.body;
  const defaultFetch = typeof windowObject?.fetch === 'function'
    ? windowObject.fetch.bind(windowObject)
    : typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;
  const relay = configuration?.relay ?? (configuration?.controller ? null : createSameOriginWalletRelay({
    fetch: configuration?.fetch ?? defaultFetch,
    location: configuration?.location ?? windowObject?.location,
  }));
  const registry = configuration?.registry ?? defaultRegistry;
  const controller = configuration?.controller ?? new WalletOriginController({
    ...configuration,
    document: documentObject,
    registry,
    relay,
    window: windowObject,
  });
  const makeCredentialPrompt = configuration?.credentialPrompt
    ?? ((options) => createPasswordCredentialPrompt(options));
  let accountSurface = null;
  let retainedIdentity = null;
  let activePrompt = null;
  let startPromise = null;
  let stopPromise = null;
  let lifecycle = [];
  let lifecycleGeneration = 0;
  let lifecycleClosed = false;

  const clearPublicAccount = () => {
    const cleaned = accountSurface?.destroy?.() ?? true;
    if (cleaned) accountSurface = null;
    retainedIdentity = null;
  };
  const clearRenderedMount = () => {
    try { mount?.replaceChildren?.(); } catch { /* lifecycle cleanup remains best effort */ }
  };
  const advanceLifecycleGeneration = () => {
    lifecycleGeneration = lifecycleGeneration >= Number.MAX_SAFE_INTEGER
      ? 1
      : lifecycleGeneration + 1;
    return lifecycleGeneration;
  };
  const invalidateLifecycle = () => {
    lifecycleClosed = true;
    advanceLifecycleGeneration();
  };
  const isLifecycleCurrent = (generation) => !lifecycleClosed
    && lifecycleGeneration === generation;
  const assertLifecycleCurrent = (generation) => {
    if (!isLifecycleCurrent(generation)) throw new WalletOriginError('STALE_CONTROLLER');
  };
  const releasePrompt = (prompt) => {
    try { prompt?.remove?.(); } catch { /* terminal cleanup remains best effort */ }
    if (activePrompt === prompt) activePrompt = null;
  };
  const clearOnLifecycle = () => {
    invalidateLifecycle();
    activePrompt?.cancel?.();
    activePrompt = null;
    clearPublicAccount();
    clearRenderedMount();
  };
  const bindLifecycle = (target, type, listener) => {
    target?.addEventListener?.(type, listener);
    lifecycle.push([target, type, listener]);
  };
  const detachLifecycle = () => {
    for (const [target, type, listener] of lifecycle) {
      try { target?.removeEventListener?.(type, listener); } catch { /* best effort */ }
    }
    lifecycle = [];
  };
  bindLifecycle(windowObject, 'pagehide', clearOnLifecycle);
  bindLifecycle(documentObject, 'freeze', clearOnLifecycle);
  bindLifecycle(windowObject, 'beforeunload', clearOnLifecycle);
  bindLifecycle(windowObject, 'pageshow', (event) => {
    if (event?.persisted === true) clearOnLifecycle();
  });
  return Object.freeze({
    controller,
    logout() {
      if (accountSurface) return accountSurface.logout();
      invalidateLifecycle();
      activePrompt?.cancel?.();
      activePrompt = null;
      retainedIdentity = null;
      return controller.logout();
    },
    start() {
      if (startPromise) return startPromise;
      const runGeneration = lifecycleGeneration;
      if (lifecycleClosed) {
        startPromise = Promise.reject(new WalletOriginError('STALE_CONTROLLER'));
        return startPromise;
      }
      startPromise = (async () => {
        try {
          const transactionId = transactionIdFromLocation(windowObject?.location);
          // Compatibility seam for controller doubles; the production controller
          // always takes the validate-before-credentials path below.
          if (typeof controller.prepare !== 'function'
              || typeof controller.executePrepared !== 'function'
              || typeof controller.unlockPassword !== 'function') {
            const result = await controller.execute(transactionId);
            assertLifecycleCurrent(runGeneration);
            return result;
          }
          const transaction = await controller.prepare(transactionId);
          assertLifecycleCurrent(runGeneration);
          const rawV1 = transaction.transaction.operation === 'sdn.auth.raw-challenge.v1';
          if (rawV1) {
            const profilePrompt = createLegacyProfilePrompt({
              document: documentObject,
              mount,
              title: `Choose the legacy profile for ${transaction.binding.clientDisplayName}`,
            });
            activePrompt = profilePrompt;
            const profile = await profilePrompt.promise;
            assertLifecycleCurrent(runGeneration);
            if (activePrompt === profilePrompt) activePrompt = null;
            const promptResult = profile === 'password-fast-v1-legacy'
              ? makeCredentialPrompt({
                controller: null,
                document: documentObject,
                mount,
                title: `Sign in to ${transaction.binding.clientDisplayName}`,
                transaction,
              })
              : createMnemonicCredentialPrompt({
                document: documentObject,
                mount,
                submitLabel: 'Continue',
                title: `Sign in to ${transaction.binding.clientDisplayName}`,
              });
            activePrompt = promptResult?.promise ? promptResult : null;
            const controls = promptResult?.promise ? await promptResult.promise : await promptResult;
            assertLifecycleCurrent(runGeneration);
            const unlockedIdentity = await controller.unlockLegacy({
              ...controls,
              operation: transaction.transaction.operation,
              profile,
            });
            assertLifecycleCurrent(runGeneration);
            retainedIdentity = unlockedIdentity;
          } else {
            let restoreFailed = false;
            for (;;) {
              const promptResult = makeCredentialPrompt({
                controller,
                document: documentObject,
                mount,
                offerRememberedUnlock: !restoreFailed,
                title: `Sign in to ${transaction.binding.clientDisplayName}`,
                transaction,
              });
              if (restoreFailed && promptResult?.controls?.rememberStatus) {
                promptResult.controls.rememberStatus.textContent = 'Remembered wallet unavailable. Enter username and password.';
              }
              activePrompt = promptResult?.promise ? promptResult : null;
              const controls = promptResult?.promise ? await promptResult.promise : await promptResult;
              assertLifecycleCurrent(runGeneration);
              if (controls?.remembered === true) {
                try {
                  const unlockedIdentity = await controller.unlockRemembered();
                  assertLifecycleCurrent(runGeneration);
                  retainedIdentity = unlockedIdentity;
                  break;
                } catch (error) {
                  if (!isLifecycleCurrent(runGeneration)) {
                    releasePrompt(promptResult);
                    throw new WalletOriginError('STALE_CONTROLLER');
                  }
                  restoreFailed = true;
                  releasePrompt(promptResult);
                  continue;
                }
              }
              const unlockedIdentity = await controller.unlockPassword(controls);
              assertLifecycleCurrent(runGeneration);
              retainedIdentity = unlockedIdentity;
              break;
            }
          }
          const publication = await controller.executePrepared(transaction);
          assertLifecycleCurrent(runGeneration);
          releasePrompt(activePrompt);
          if (transaction.transaction.operation === 'sdn.wallet.account.v1') {
            retainedIdentity = controller.copyPublicIdentity();
            accountSurface = installAccountSurface({
              clipboard: configuration?.clipboard ?? globalThis.navigator?.clipboard,
              controller,
              document: documentObject,
              identity: retainedIdentity,
              isAppCurrent: () => isLifecycleCurrent(runGeneration),
              makeCredentialPrompt,
              mount,
              onClear: clearPublicAccount,
              wasm: configuration?.wasm,
            });
          } else {
            retainedIdentity = null;
            if (documentObject?.createElement && mount?.replaceChildren) {
              renderCompletion(
                documentObject,
                windowObject,
                'The wallet request completed successfully.',
                mount,
              );
            }
          }
          return publication;
        } catch (error) {
          const stale = !isLifecycleCurrent(runGeneration);
          activePrompt?.cancel?.();
          activePrompt = null;
          clearPublicAccount();
          detachLifecycle();
          if (!stale) {
            renderFailure(documentObject, error?.code === 'USER_CANCELLED'
              ? 'Cancelled. You may close this window.'
              : undefined, mount);
          }
          await (stopPromise ?? controller.destroy(stale ? 'stale-startup' : 'startup-failure'));
          if (stale && error?.code !== 'DESTRUCTION_FAILED') {
            throw new WalletOriginError('STALE_CONTROLLER');
          }
          throw error;
        }
      })();
      return startPromise;
    },
    stop(reason = 'close') {
      invalidateLifecycle();
      activePrompt?.cancel?.();
      activePrompt = null;
      clearPublicAccount();
      clearRenderedMount();
      const destroyAttempt = controller.destroy(reason);
      if (!stopPromise) {
        detachLifecycle();
        stopPromise = destroyAttempt;
      }
      return stopPromise;
    },
  });
}

export async function mountWalletOriginApp(configuration) {
  const app = createWalletOriginApp(configuration);
  await app.start();
  return app;
}
