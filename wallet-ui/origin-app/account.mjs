import { ACTIVE_REMEMBERED_WALLET_KEY } from '../src/wallet-storage.js';

const MODERN_IDENTITY_SCHEME = 'sdn-bip32-slip10-purpose-v1';
const MODERN_SEED_PROFILE = 'password-scrypt-v2';
const APPROVAL_PATH = "m/44'/0'/0'/2'/0'";
const APPROVAL_UNAVAILABLE = 'Approval unavailable — migrate to the new wallet profile';
const LEGACY_PROFILE_SCHEMES = Object.freeze({
  'bip39-mnemonic-v1-legacy': 'sdn-bip39-auth-v1-legacy',
  'password-fast-v1-legacy': 'sdn-fast-password-auth-v1-legacy',
});
const encoder = new TextEncoder();
const intrinsicFill = Uint8Array.prototype.fill;
const PUBLIC_IDENTITY_FIELDS = Object.freeze([
  'accountFingerprint',
  'accountIndex',
  'accountLabel',
  'accountPeerId',
  'accountXpub',
  'identityScheme',
  'keys',
  'schemaVersion',
  'seedProfile',
]);
const KEY_DESCRIPTOR_FIELDS = Object.freeze([
  'bip32Fingerprint',
  'curve',
  'derivation',
  'encoding',
  'identityScheme',
  'keyId',
  'path',
  'publicKeyHex',
  'purpose',
  'seedProfile',
  'signatureProfile',
]);
const EXPECTED_KEYS = Object.freeze([
  Object.freeze({
    curve: 'ed25519',
    path: APPROVAL_PATH,
    purpose: 'asset-review-approval',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  }),
  Object.freeze({
    curve: 'x25519',
    path: "m/44'/0'/0'/1'/0'",
    purpose: 'contact-encryption',
    signatureProfile: null,
  }),
  Object.freeze({
    curve: 'ed25519',
    path: "m/44'/0'/0'/0'/0'",
    purpose: 'sdn-authentication',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  }),
]);

export class WalletAccountError extends Error {
  constructor(code) {
    super(code === 'APPROVAL_UNAVAILABLE' ? APPROVAL_UNAVAILABLE : code);
    this.name = 'WalletAccountError';
    this.code = code;
  }
}

function fail(code) {
  throw new WalletAccountError(code);
}

function wipe(bytes) {
  if (!(bytes instanceof Uint8Array)) return;
  try { intrinsicFill.call(bytes, 0); } catch { /* detached buffers are no longer usable */ }
}

function deepFreezeCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(deepFreezeCopy));
  if (!value || typeof value !== 'object') return value;
  const copy = {};
  for (const key of Object.keys(value).sort()) copy[key] = deepFreezeCopy(value[key]);
  return Object.freeze(copy);
}

function isRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(value, fields) {
  if (!isRecord(value)) fail('INVALID_PUBLIC_IDENTITY');
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { fail('INVALID_PUBLIC_IDENTITY'); }
  if (keys.some((key) => typeof key !== 'string')) fail('INVALID_PUBLIC_IDENTITY');
  const actual = [...keys].sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) fail('INVALID_PUBLIC_IDENTITY');
  const output = {};
  for (const field of actual) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, field); } catch { fail('INVALID_PUBLIC_IDENTITY'); }
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      fail('INVALID_PUBLIC_IDENTITY');
    }
    output[field] = descriptor.value;
  }
  return output;
}

function wellFormedString(value) {
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

function exactThreeElementArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || value.length !== EXPECTED_KEYS.length) return false;
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { return false; }
  const expected = ['0', '1', '2', 'length'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return false;
  for (let index = 0; index < EXPECTED_KEYS.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}

function exactOneElementArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || value.length !== 1) return false;
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { return false; }
  if (keys.length !== 2 || keys[0] !== '0' || keys[1] !== 'length') return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, '0');
  return descriptor?.enumerable === true && 'value' in descriptor;
}

export function copyModernPublicIdentity(input) {
  const value = exactRecord(input, PUBLIC_IDENTITY_FIELDS);
  if (value.schemaVersion !== 1 || value.identityScheme !== MODERN_IDENTITY_SCHEME
      || value.seedProfile !== MODERN_SEED_PROFILE || value.accountIndex !== 0
      || value.accountLabel !== null || !/^[0-9a-f]{8}$/u.test(value.accountFingerprint)
      || !wellFormedString(value.accountXpub) || !/^xpub[1-9A-HJ-NP-Za-km-z]{107}$/u.test(value.accountXpub)
      || !wellFormedString(value.accountPeerId) || !/^16Uiu2H[1-9A-HJ-NP-Za-km-z]{33,57}$/u.test(value.accountPeerId)
      || !exactThreeElementArray(value.keys)) {
    fail('INVALID_PUBLIC_IDENTITY');
  }
  const keys = EXPECTED_KEYS.map((expected, index) => {
    const descriptor = exactRecord(value.keys[index], KEY_DESCRIPTOR_FIELDS);
    if (descriptor.bip32Fingerprint !== null || descriptor.curve !== expected.curve
        || descriptor.derivation !== 'slip10' || descriptor.encoding !== 'raw'
        || descriptor.identityScheme !== MODERN_IDENTITY_SCHEME
        || descriptor.path !== expected.path || descriptor.purpose !== expected.purpose
        || descriptor.seedProfile !== MODERN_SEED_PROFILE
        || descriptor.signatureProfile !== expected.signatureProfile
        || !/^[0-9a-f]{64}$/u.test(descriptor.publicKeyHex)
        || !/^sha256:[0-9a-f]{64}$/u.test(descriptor.keyId)) {
      fail('INVALID_PUBLIC_IDENTITY');
    }
    return deepFreezeCopy(descriptor);
  });
  return deepFreezeCopy({ ...value, keys });
}

export function copyLegacyPublicIdentity(input, { accountIndex = 0, profile } = {}) {
  const identityScheme = Object.hasOwn(LEGACY_PROFILE_SCHEMES, profile)
    ? LEGACY_PROFILE_SCHEMES[profile]
    : null;
  if (!identityScheme || accountIndex !== 0) fail('INVALID_LEGACY_PROFILE');
  const value = exactRecord(input, PUBLIC_IDENTITY_FIELDS);
  if (value.schemaVersion !== 1 || value.identityScheme !== identityScheme
      || value.seedProfile !== profile || value.accountIndex !== accountIndex
      || value.accountLabel !== null || !/^[0-9a-f]{8}$/u.test(value.accountFingerprint)
      || !wellFormedString(value.accountXpub) || !/^xpub[1-9A-HJ-NP-Za-km-z]{107}$/u.test(value.accountXpub)
      || !wellFormedString(value.accountPeerId) || !/^16Uiu2H[1-9A-HJ-NP-Za-km-z]{33,57}$/u.test(value.accountPeerId)
      || !exactOneElementArray(value.keys)) {
    fail('INVALID_PUBLIC_IDENTITY');
  }
  const descriptor = exactRecord(value.keys[0], KEY_DESCRIPTOR_FIELDS);
  if (descriptor.bip32Fingerprint !== null || descriptor.curve !== 'ed25519'
      || descriptor.derivation !== 'bip32-scalar-as-ed25519-seed'
      || descriptor.encoding !== 'raw' || descriptor.identityScheme !== identityScheme
      || descriptor.path !== `m/44'/0'/${accountIndex}'/0/0`
      || descriptor.purpose !== 'sdn-authentication' || descriptor.seedProfile !== profile
      || descriptor.signatureProfile !== 'ed25519-raw-32-v1'
      || !/^[0-9a-f]{64}$/u.test(descriptor.publicKeyHex)
      || !/^sha256:[0-9a-f]{64}$/u.test(descriptor.keyId)) {
    fail('INVALID_PUBLIC_IDENTITY');
  }
  return deepFreezeCopy({ ...value, keys: [descriptor] });
}

function clearCredentialControl(control) {
  if (!control || typeof control !== 'object') return;
  try { control.value = ''; } catch { /* continue */ }
  try { control.defaultValue = ''; } catch { /* continue */ }
  try { control.disabled = true; } catch { /* continue */ }
  try { control.inert = true; } catch { /* continue */ }
  try { control.removeAttribute?.('name'); } catch { /* continue */ }
  try { control.removeAttribute?.('autocomplete'); } catch { /* continue */ }
  try { control.setSelectionRange?.(0, 0); } catch { /* continue */ }
  try { control.setCustomValidity?.(''); } catch { /* continue */ }
}

function constantHexEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const maximum = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximum; index += 2) {
    const leftByte = Number.parseInt(left.slice(index, index + 2), 16);
    const rightByte = Number.parseInt(right.slice(index, index + 2), 16);
    difference |= (Number.isNaN(leftByte) ? 256 : leftByte)
      ^ (Number.isNaN(rightByte) ? 256 : rightByte);
  }
  return difference === 0;
}

function approvalDescriptor(identity) {
  if (!identity || typeof identity !== 'object' || !Array.isArray(identity.keys)) return null;
  return identity.keys.find((descriptor) => descriptor?.purpose === 'asset-review-approval') ?? null;
}

function publicIdentityMatches(left, right) {
  try {
    left = copyModernPublicIdentity(left);
    right = copyModernPublicIdentity(right);
  } catch {
    return false;
  }
  let match = true;
  for (const field of PUBLIC_IDENTITY_FIELDS.filter((field) => field !== 'keys')) {
    match = (left[field] === right[field]) && match;
  }
  for (let index = 0; index < EXPECTED_KEYS.length; index += 1) {
    const leftKey = left.keys[index];
    const rightKey = right.keys[index];
    for (const field of KEY_DESCRIPTOR_FIELDS
      .filter((field) => field !== 'publicKeyHex' && field !== 'keyId')) {
      match = (leftKey[field] === rightKey[field]) && match;
    }
    match = constantHexEqual(leftKey.publicKeyHex, rightKey.publicKeyHex) && match;
    match = constantHexEqual(leftKey.keyId.slice(7), rightKey.keyId.slice(7)) && match;
  }
  return match;
}

function appendValue(document, container, label, value) {
  const row = document.createElement('div');
  row.className = 'wallet-account-row';
  const labelNode = document.createElement('strong');
  labelNode.textContent = `${label}: `;
  const valueNode = document.createElement('span');
  valueNode.textContent = value === null || value === undefined ? '' : String(value);
  row.append(labelNode, valueNode);
  container.append(row);
}

export function createApprovalConfiguration(identity) {
  if (identity?.identityScheme !== MODERN_IDENTITY_SCHEME
      || identity?.seedProfile !== MODERN_SEED_PROFILE || identity?.accountIndex !== 0) {
    fail('APPROVAL_UNAVAILABLE');
  }
  const approval = approvalDescriptor(identity);
  if (!approval || approval.identityScheme !== identity.identityScheme
      || approval.seedProfile !== identity.seedProfile
      || approval.signatureProfile !== 'ed25519-over-sha256-jcs-v1'
      || approval.curve !== 'ed25519' || approval.derivation !== 'slip10'
      || approval.path !== APPROVAL_PATH || approval.encoding !== 'raw'
      || !/^[0-9a-f]{64}$/u.test(approval.publicKeyHex)
      || !/^sha256:[0-9a-f]{64}$/u.test(approval.keyId)) {
    fail('APPROVAL_UNAVAILABLE');
  }
  return deepFreezeCopy({
    algorithm: 'Ed25519',
    derivationPath: APPROVAL_PATH,
    encoding: 'raw-32-byte',
    identityScheme: identity.identityScheme,
    keyId: approval.keyId,
    publicKeyHex: approval.publicKeyHex,
    purpose: 'asset-review-approval',
    schemaVersion: 1,
    seedProfile: identity.seedProfile,
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  });
}

export function serializeApprovalConfiguration(configuration) {
  return JSON.stringify(configuration, null, 2);
}

export function renderAccount(container, identity, { document = container.ownerDocument } = {}) {
  container.replaceChildren();
  const heading = document.createElement('h1');
  heading.textContent = 'Account';
  container.append(heading);
  appendValue(document, container, 'Username / account', identity?.accountLabel ?? 'account 0');
  appendValue(document, container, 'Account xpub', identity?.accountXpub);
  appendValue(document, container, 'Peer ID', identity?.accountPeerId);
  appendValue(document, container, 'Fingerprint', identity?.accountFingerprint);
  if (identity?.identityScheme !== MODERN_IDENTITY_SCHEME
      || identity?.seedProfile !== MODERN_SEED_PROFILE) {
    const unavailable = document.createElement('p');
    unavailable.textContent = APPROVAL_UNAVAILABLE;
    container.append(unavailable);
    return Object.freeze({ approvalAvailable: false });
  }
  const configuration = createApprovalConfiguration(identity);
  appendValue(document, container, 'Asset approval public key', configuration.publicKeyHex);
  appendValue(document, container, 'Asset approval key ID', configuration.keyId);
  return Object.freeze({ approvalAvailable: true, configuration });
}

export function renderRememberedWalletForget(
  container,
  { document = container.ownerDocument } = {},
) {
  container.replaceChildren();
  const heading = document.createElement('h2');
  heading.textContent = 'Stored wallet';
  const explanation = document.createElement('p');
  explanation.textContent = 'Forgetting removes the saved unlock record but keeps this account signed in.';
  const launch = document.createElement('button');
  launch.type = 'button';
  launch.dataset.walletAction = 'forget-stored-wallet';
  launch.textContent = 'Forget stored wallet';
  const confirmationGroup = document.createElement('div');
  confirmationGroup.hidden = true;
  const instruction = document.createElement('p');
  instruction.textContent = `Type ${ACTIVE_REMEMBERED_WALLET_KEY} to confirm.`;
  const confirmation = document.createElement('input');
  confirmation.type = 'text';
  confirmation.autocomplete = 'off';
  confirmation.spellcheck = false;
  confirmation.dataset.walletForgetConfirmation = 'exact-storage-key';
  const confirm = document.createElement('button');
  confirm.type = 'button';
  confirm.dataset.walletAction = 'confirm-forget-stored-wallet';
  confirm.textContent = 'Confirm forget';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel-forget-stored-wallet';
  cancel.textContent = 'Cancel';
  const status = document.createElement('p');
  status.dataset.walletForgetStatus = 'true';
  status.setAttribute?.('aria-live', 'polite');
  confirmationGroup.append(instruction, confirmation, confirm, cancel);
  container.append(heading, explanation, launch, confirmationGroup, status);
  return Object.freeze({
    cancel,
    confirm,
    confirmation,
    confirmationGroup,
    confirmationKey: ACTIVE_REMEMBERED_WALLET_KEY,
    launch,
    status,
  });
}

export function renderQuarantinedWalletManager(
  container,
  entries,
  { document = container.ownerDocument } = {},
) {
  container.replaceChildren();
  const heading = document.createElement('h2');
  heading.textContent = 'Quarantined wallet storage';
  const explanation = document.createElement('p');
  explanation.textContent = 'These records are never unlocked automatically. Export or delete each exact storage key.';
  const list = document.createElement('div');
  const status = document.createElement('p');
  status.dataset.walletQuarantineStatus = 'true';
  status.setAttribute?.('aria-live', 'polite');
  const rows = [];
  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = 'wallet-quarantine-row';
    const label = document.createElement('code');
    label.dataset.walletQuarantineLabel = 'true';
    label.textContent = entry.key;
    const detail = document.createElement('span');
    detail.textContent = entry.oversized
      ? `Export unavailable (${entry.rawLength} characters)`
      : `${entry.rawLength} characters`;
    const exportButton = document.createElement('button');
    exportButton.type = 'button';
    exportButton.dataset.walletAction = 'export-quarantined-wallet';
    exportButton.dataset.walletQuarantineKey = entry.key;
    exportButton.textContent = entry.exportable ? 'Export' : 'Export unavailable';
    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.dataset.walletAction = 'delete-quarantined-wallet';
    deleteButton.dataset.walletQuarantineKey = entry.key;
    deleteButton.textContent = 'Delete';
    const confirmationGroup = document.createElement('div');
    confirmationGroup.hidden = true;
    const instruction = document.createElement('p');
    instruction.textContent = `Type ${entry.key} to confirm deletion.`;
    const confirmation = document.createElement('input');
    confirmation.type = 'text';
    confirmation.autocomplete = 'off';
    confirmation.spellcheck = false;
    confirmation.dataset.walletQuarantineConfirmation = entry.key;
    const confirm = document.createElement('button');
    confirm.type = 'button';
    confirm.dataset.walletAction = 'confirm-delete-quarantined-wallet';
    confirm.dataset.walletQuarantineKey = entry.key;
    confirm.textContent = 'Confirm delete';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.dataset.walletAction = 'cancel-delete-quarantined-wallet';
    cancel.dataset.walletQuarantineKey = entry.key;
    cancel.textContent = 'Cancel';
    confirmationGroup.append(instruction, confirmation, confirm, cancel);
    row.append(label, detail, exportButton, deleteButton, confirmationGroup);
    list.append(row);
    rows.push(Object.freeze({
      cancel,
      confirm,
      confirmation,
      confirmationGroup,
      deleteButton,
      entry,
      exportButton,
    }));
  }
  container.append(heading, explanation, list, status);
  return Object.freeze({ rows: Object.freeze(rows), status });
}

export async function copyApprovalConfiguration(
  configuration,
  {
    assertCurrent = () => {},
    clipboard = globalThis.navigator?.clipboard,
    container,
    document = container?.ownerDocument,
  },
) {
  const json = serializeApprovalConfiguration(configuration);
  let copied = false;
  try {
    if (!clipboard?.writeText) throw new Error('clipboard unavailable');
    await clipboard.writeText(json);
    copied = true;
  } catch { /* fallback is rendered only while the owning surface is current */ }
  assertCurrent();
  if (!copied && container && document) {
    const textarea = document.createElement('textarea');
    textarea.readOnly = true;
    textarea.value = json;
    textarea.textContent = json;
    container.replaceChildren(textarea);
    try { textarea.select?.(); } catch { /* remains selectable manually */ }
  }
  return copied;
}

async function deriveRound(wasm, credentialRound, round, {
  assertCurrent,
  ownBuffer,
  ownHandle,
  releaseBuffer,
}) {
  const controls = await credentialRound(round);
  const usernameControl = controls?.usernameControl;
  const passwordControl = controls?.passwordControl;
  let usernameUtf8;
  let passwordUtf8;
  try {
    assertCurrent();
    const username = usernameControl?.value;
    const password = passwordControl?.value;
    if (typeof username !== 'string' || typeof password !== 'string') {
      fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    }
    if (!wellFormedString(username) || !wellFormedString(password)) {
      fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    }
    usernameUtf8 = encoder.encode(username);
    ownBuffer(usernameUtf8);
    passwordUtf8 = encoder.encode(password);
    ownBuffer(passwordUtf8);
  } finally {
    clearCredentialControl(usernameControl);
    clearCredentialControl(passwordControl);
    const usernameForm = usernameControl?.form;
    const passwordForm = passwordControl?.form;
    try { (usernameForm?.parentNode ?? usernameForm)?.remove?.(); } catch { /* fields were already cleared */ }
    if (passwordForm !== usernameForm) {
      try { (passwordForm?.parentNode ?? passwordForm)?.remove?.(); } catch { /* fields were already cleared */ }
    }
  }
  let result;
  try {
    assertCurrent();
    result = await wasm.derivePasswordIdentity({
      accountIndex: 0,
      passwordUtf8,
      usernameUtf8,
    });
    if (!result?.handle) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    ownHandle(result.handle);
    assertCurrent();
    let identity;
    try { identity = copyModernPublicIdentity(result.identity); } catch { fail('CREDENTIAL_CONFIRMATION_MISMATCH'); }
    return { handle: result.handle, identity };
  } finally {
    releaseBuffer(usernameUtf8);
    releaseBuffer(passwordUtf8);
  }
}

export class ApprovalConfigurationController {
  #confirmed = null;
  #credentialRound;
  #destroyed = false;
  #destroyingHandles = new Set();
  #expectedIdentity;
  #generation = 0;
  #inFlight = 0;
  #ownedHandles = new Set();
  #secretBuffers = new Set();
  #wasm;

  constructor({ wasm, credentialRound, expectedIdentity = null }) {
    this.#wasm = wasm?.sdn ?? wasm;
    this.#credentialRound = credentialRound;
    try {
      this.#expectedIdentity = expectedIdentity === null
        ? null
        : copyModernPublicIdentity(expectedIdentity);
    } catch {
      fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    }
    if (typeof this.#wasm?.derivePasswordIdentity !== 'function'
        || typeof this.#wasm?.destroySdnIdentity !== 'function'
        || typeof credentialRound !== 'function') fail('CREDENTIAL_CONFIRMATION_MISMATCH');
  }

  get confirmed() {
    return this.#confirmed;
  }

  clear() {
    this.#confirmed = null;
    if (!this.#destroyed) {
      this.#destroyed = true;
      this.#generation += 1;
      this.#expectedIdentity = null;
    }
    this.#clearSecretBuffers();
    this.#cleanupOwnedHandles();
    return this.#inFlight === 0 && this.#ownedHandles.size === 0;
  }

  destroy() {
    return this.clear();
  }

  async confirm() {
    if (this.#destroyed) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    if (this.#confirmed) return this.#confirmed;
    this.#inFlight += 1;
    const generation = this.#generation;
    let first;
    let second;
    try {
      this.#cleanupOwnedHandles();
      if (this.#ownedHandles.size !== 0) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
      const ownHandle = (handle) => this.#ownedHandles.add(handle);
      const roundOwnership = {
        assertCurrent: () => this.#assertCurrent(generation),
        ownBuffer: (bytes) => this.#secretBuffers.add(bytes),
        ownHandle,
        releaseBuffer: (bytes) => {
          wipe(bytes);
          this.#secretBuffers.delete(bytes);
        },
      };
      first = await deriveRound(this.#wasm, this.#credentialRound, 1, roundOwnership);
      if (!this.#destroyOwnedHandle(first.handle)) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
      first.handle = null;
      this.#assertCurrent(generation);
      second = await deriveRound(this.#wasm, this.#credentialRound, 2, roundOwnership);
      if (!this.#destroyOwnedHandle(second.handle)) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
      second.handle = null;
      this.#assertCurrent(generation);
      if (!publicIdentityMatches(first.identity, second.identity)
          || (this.#expectedIdentity !== null
            && (!publicIdentityMatches(first.identity, this.#expectedIdentity)
              || !publicIdentityMatches(second.identity, this.#expectedIdentity)))) {
        fail('CREDENTIAL_CONFIRMATION_MISMATCH');
      }
      if (this.#ownedHandles.size !== 0) fail('CREDENTIAL_CONFIRMATION_MISMATCH');
      this.#confirmed = createApprovalConfiguration(second.identity);
      return this.#confirmed;
    } catch (error) {
      this.#confirmed = null;
      if (error instanceof WalletAccountError
          && error.code === 'CREDENTIAL_CONFIRMATION_MISMATCH') throw error;
      fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    } finally {
      this.#clearSecretBuffers();
      this.#cleanupOwnedHandles();
      this.#inFlight -= 1;
    }
  }

  #assertCurrent(generation) {
    if (this.#destroyed || this.#generation !== generation) {
      fail('CREDENTIAL_CONFIRMATION_MISMATCH');
    }
  }

  #destroyOwnedHandle(handle) {
    if (!this.#ownedHandles.has(handle)) return true;
    if (this.#destroyingHandles.has(handle)) return false;
    this.#destroyingHandles.add(handle);
    try {
      this.#wasm.destroySdnIdentity(handle);
      this.#ownedHandles.delete(handle);
      return true;
    } catch {
      return false;
    } finally {
      this.#destroyingHandles.delete(handle);
    }
  }

  #cleanupOwnedHandles() {
    for (const handle of [...this.#ownedHandles]) this.#destroyOwnedHandle(handle);
  }

  #clearSecretBuffers() {
    const buffers = [...this.#secretBuffers];
    this.#secretBuffers.clear();
    for (const bytes of buffers) wipe(bytes);
  }
}

export async function deriveExplicitLegacyIdentity({
  wasm,
  profile,
  operation,
  credentials,
  accountIndex = 0,
  assertCurrent = () => {},
  ownHandle = () => {},
}) {
  if (operation !== 'sdn.auth.raw-challenge.v1') fail('OPERATION_NOT_ALLOWED');
  const capabilities = wasm?.sdn ?? wasm;
  let result;
  if (profile === 'password-fast-v1-legacy') {
    if (typeof capabilities?.deriveLegacyPasswordIdentity !== 'function') fail('INVALID_LEGACY_PROFILE');
    result = await capabilities.deriveLegacyPasswordIdentity({ accountIndex, ...credentials });
  } else if (profile === 'bip39-mnemonic-v1-legacy') {
    if (typeof capabilities?.importLegacyMnemonicIdentity !== 'function') fail('INVALID_LEGACY_PROFILE');
    result = await capabilities.importLegacyMnemonicIdentity({ accountIndex, ...credentials });
  } else {
    fail('INVALID_LEGACY_PROFILE');
  }
  if (result?.handle !== null && result?.handle !== undefined) ownHandle(result.handle);
  assertCurrent();
  return Object.freeze({
    approval: null,
    handle: result.handle,
    identity: deepFreezeCopy(result.identity),
    legacy: true,
  });
}

export function renderLegacyMigrationLauncher(container, { document = container.ownerDocument } = {}) {
  container.replaceChildren();
  const heading = document.createElement('h2');
  heading.textContent = 'Migrate legacy wallet';
  const explanation = document.createElement('p');
  explanation.textContent = 'Select the exact legacy profile and compare its legacy xpub and authentication key.';
  const select = document.createElement('select');
  select.dataset.walletLegacyProfile = 'required';
  for (const [value, label] of [
    ['password-fast-v1-legacy', 'Legacy fast-password profile'],
    ['bip39-mnemonic-v1-legacy', 'Legacy BIP-39 mnemonic import'],
  ]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    select.append(option);
  }
  const launch = document.createElement('button');
  launch.type = 'button';
  launch.dataset.walletAction = 'launch-legacy-migration';
  launch.textContent = 'Compare selected legacy account';
  const result = document.createElement('div');
  result.className = 'wallet-legacy-comparison';
  container.append(heading, explanation, select, launch, result);
  return Object.freeze({ launch, result, select });
}

export { APPROVAL_UNAVAILABLE };
