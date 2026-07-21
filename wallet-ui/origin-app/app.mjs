import { WalletOriginController, WalletOriginError } from './controller.mjs';
import {
  APPROVAL_UNAVAILABLE,
  ApprovalConfigurationController,
  copyApprovalConfiguration,
  deriveExplicitLegacyIdentity,
  renderAccount,
  renderLegacyMigrationLauncher,
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

export function createPasswordCredentialPrompt({
  controller = null,
  document,
  mount = null,
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
  const actions = document.createElement('div');
  actions.className = 'wallet-login-actions';
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.dataset.walletAction = 'login';
  submit.textContent = 'Login';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel-login';
  cancel.textContent = 'Cancel';
  actions.append(submit, cancel);
  form.append(actions);
  section.append(heading, account, form);
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
  };
  const rejectAndClear = (code) => {
    if (settled) return;
    settled = true;
    cleanupListeners();
    try { controller?.revokeNow?.(code); } catch { /* local form cleanup still runs */ }
    clearCredentialForm(form, [usernameControl, passwordControl]);
    section.remove?.();
    rejectPromise(new WalletOriginError(code));
  };
  const onSubmit = (event) => {
    event?.preventDefault?.();
    if (settled || event?.isTrusted !== true) return;
    settled = true;
    cleanupListeners();
    resolvePromise({ passwordControl, usernameControl });
  };
  const onCancel = (event) => {
    if (event?.isTrusted !== true) return;
    rejectAndClear('USER_CANCELLED');
  };
  form.addEventListener('submit', onSubmit);
  cancel.addEventListener('click', onCancel);
  try { usernameControl.focus?.(); } catch { /* focus is best effort */ }
  return Object.freeze({
    cancel: () => rejectAndClear('STALE_CONTROLLER'),
    controls: Object.freeze({ passwordControl, usernameControl }),
    form,
    promise,
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
  const rejectAndClear = () => {
    if (settled) return;
    settled = true;
    cleanupListeners();
    clearCredentialForm(form, [mnemonicControl]);
    section.remove?.();
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
  return Object.freeze({ cancel: rejectAndClear, promise });
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
  const exitStatus = document.createElement('p');
  exitStatus.className = 'wallet-account-exit-status';
  section.append(accountView, approvalCard, returnToSite, logout, migration);
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
    const busy = copying || migrationRunning;
    returnToSite.disabled = finishing;
    logout.disabled = finishing;
    if (!destroyed) {
      copy.disabled = busy || !rendered.approvalAvailable;
      legacyLauncher.launch.disabled = busy;
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
    if (event?.isTrusted !== true || copying || migrationRunning) return;
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
    if (event?.isTrusted !== true || migrationRunning || copying) return;
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
  const terminalizeSurface = (retainExitSurface) => {
    if (!destroyed) {
      destroyed = true;
      surfaceGeneration += 1;
      copy.disabled = true;
      legacyLauncher.launch.disabled = true;
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
        return await action();
      } catch (error) {
        renderFailure(document, undefined, mount);
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

  const clearPublicAccount = () => {
    const cleaned = accountSurface?.destroy?.() ?? true;
    if (cleaned) accountSurface = null;
    retainedIdentity = null;
  };
  const clearOnLifecycle = () => {
    activePrompt?.cancel?.();
    activePrompt = null;
    clearPublicAccount();
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
      activePrompt?.cancel?.();
      activePrompt = null;
      if (accountSurface) return accountSurface.logout();
      retainedIdentity = null;
      return controller.logout();
    },
    start() {
      if (startPromise) return startPromise;
      startPromise = (async () => {
        try {
          const transactionId = transactionIdFromLocation(windowObject?.location);
          // Compatibility seam for controller doubles; the production controller
          // always takes the validate-before-credentials path below.
          if (typeof controller.prepare !== 'function'
              || typeof controller.executePrepared !== 'function'
              || typeof controller.unlockPassword !== 'function') {
            return await controller.execute(transactionId);
          }
          const transaction = await controller.prepare(transactionId);
          const rawV1 = transaction.transaction.operation === 'sdn.auth.raw-challenge.v1';
          if (rawV1) {
            const profilePrompt = createLegacyProfilePrompt({
              document: documentObject,
              mount,
              title: `Choose the legacy profile for ${transaction.binding.clientDisplayName}`,
            });
            activePrompt = profilePrompt;
            const profile = await profilePrompt.promise;
            activePrompt = null;
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
            activePrompt = null;
            retainedIdentity = await controller.unlockLegacy({
              ...controls,
              operation: transaction.transaction.operation,
              profile,
            });
          } else {
            const promptResult = makeCredentialPrompt({
              controller,
              document: documentObject,
              mount,
              title: `Sign in to ${transaction.binding.clientDisplayName}`,
              transaction,
            });
            activePrompt = promptResult?.promise ? promptResult : null;
            const controls = promptResult?.promise ? await promptResult.promise : await promptResult;
            activePrompt = null;
            retainedIdentity = await controller.unlockPassword(controls);
          }
          const publication = await controller.executePrepared(transaction);
          if (transaction.transaction.operation === 'sdn.wallet.account.v1') {
            retainedIdentity = controller.copyPublicIdentity();
            accountSurface = installAccountSurface({
              clipboard: configuration?.clipboard ?? globalThis.navigator?.clipboard,
              controller,
              document: documentObject,
              identity: retainedIdentity,
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
          clearPublicAccount();
          detachLifecycle();
          renderFailure(documentObject, error?.code === 'USER_CANCELLED'
            ? 'Cancelled. You may close this window.'
            : undefined, mount);
          await controller.destroy('startup-failure');
          throw error;
        }
      })();
      return startPromise;
    },
    stop(reason = 'close') {
      activePrompt?.cancel?.();
      activePrompt = null;
      clearPublicAccount();
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
