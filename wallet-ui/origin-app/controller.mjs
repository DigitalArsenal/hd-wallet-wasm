import {
  WalletOperationError,
  assertWalletContext,
  disconnectedAccountResult,
  executeWalletOperation,
  requestTrustedConfirmation,
  validateWalletTransaction,
} from './operations.mjs';
import { copyLegacyPublicIdentity, copyModernPublicIdentity } from './account.mjs';
import { validateWalletRelayCompletion } from './relay.mjs';

const SafeUint8Array = Uint8Array;
const intrinsicFill = SafeUint8Array.prototype.fill;
const encoder = new TextEncoder();

export class WalletOriginError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WalletOriginError';
    this.code = code;
  }
}

function fail(code) {
  throw new WalletOriginError(code);
}

function rethrowContextError(error) {
  if (error instanceof WalletOperationError) throw new WalletOriginError(error.code);
  throw error;
}

function wipe(bytes) {
  if (!(bytes instanceof SafeUint8Array)) return;
  try {
    intrinsicFill.call(bytes, 0);
  } catch {
    // Detachment still prevents later use. Native copies are separately wiped.
  }
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

function clearControl(control) {
  if (!control || typeof control !== 'object') return;
  for (const property of ['value', 'defaultValue']) {
    try { control[property] = ''; } catch { /* continue clearing */ }
  }
  try { control.disabled = true; } catch { /* continue clearing */ }
  try { control.inert = true; } catch { /* continue clearing */ }
  for (const attribute of ['name', 'autocomplete']) {
    try { control.removeAttribute?.(attribute); } catch { /* continue clearing */ }
  }
  try { control.setSelectionRange?.(0, 0); } catch { /* non-text control */ }
  try { control.setCustomValidity?.(''); } catch { /* unsupported control */ }
  for (const property of ['onbeforeinput', 'onchange', 'oninput', 'onkeydown', 'onkeyup', 'onpaste']) {
    try { control[property] = null; } catch { /* continue clearing */ }
  }
}

function retireCredentialSubtree(document, controls) {
  const roots = new Set();
  for (const control of controls) {
    let form = null;
    try { form = control?.form ?? control?.closest?.('form') ?? null; } catch { form = null; }
    if (form) roots.add(form);
    clearControl(control);
  }
  for (const root of roots) {
    let descendants = [];
    try { descendants = root.querySelectorAll?.('input, textarea') ?? []; } catch { descendants = []; }
    for (const descendant of descendants) clearControl(descendant);
    try {
      root.inert = true;
      root.setAttribute?.('aria-hidden', 'true');
      const replacement = document.createElement('div');
      replacement.dataset.walletCredentialState = 'cleared';
      root.replaceWith?.(replacement);
      root.replaceChildren?.();
    } catch {
      try { root.remove?.(); } catch { /* best effort after fields were cleared */ }
    }
  }
}

function normalizeWasm(wasm) {
  const capabilities = wasm?.sdn ?? wasm;
  const hashOwner = wasm?.utils && typeof wasm.utils === 'object' ? wasm.utils : wasm;
  const sha256 = hashOwner?.sha256;
  if (!capabilities || typeof capabilities.derivePasswordIdentity !== 'function'
      || typeof capabilities.destroySdnIdentity !== 'function'
      || typeof sha256 !== 'function') {
    fail('WASM_UNAVAILABLE');
  }
  return Object.freeze({ capabilities, sha256: sha256.bind(hashOwner) });
}

function abortController(windowObject) {
  const Constructor = windowObject?.AbortController ?? globalThis.AbortController;
  return typeof Constructor === 'function' ? new Constructor() : null;
}

export class WalletOriginController {
  #activeTransaction = false;
  #capabilities;
  #confirmation = null;
  #controllers = new Set();
  #credentialControls = new Set();
  #destroyPromise = null;
  #destroyed = false;
  #document;
  #generation = 0;
  #handle = null;
  #identity = null;
  #lifecycle = [];
  #destroyingHandles = new Set();
  #ownedHandles = new Set();
  #pendingAccountPublication = null;
  #accountPublicationPromise = null;
  #prepared = new WeakSet();
  #preparedControllers = new WeakMap();
  #publicationPermit = null;
  #registry;
  #relay;
  #relayRevoked = false;
  #retainedIdentity = null;
  #revoked = false;
  #revocationEpoch = 0;
  #rng;
  #secretBuffers = new Set();
  #sha256;
  #window;

  constructor({ wasm, registry, relay, rng, document, window }) {
    const normalizedWasm = normalizeWasm(wasm);
    this.#capabilities = normalizedWasm.capabilities;
    this.#sha256 = normalizedWasm.sha256;
    this.#registry = registry;
    this.#relay = relay;
    this.#rng = rng;
    this.#document = document;
    this.#window = window;
    this.#installLifecycle();
  }

  get generation() {
    return this.#generation;
  }

  #advanceGeneration() {
    this.#generation = this.#generation >= Number.MAX_SAFE_INTEGER ? 1 : this.#generation + 1;
    return this.#generation;
  }

  #installLifecycle() {
    const bind = (target, type, listener) => {
      target?.addEventListener?.(type, listener);
      this.#lifecycle.push([target, type, listener]);
    };
    bind(this.#window, 'pagehide', () => this.revokeNow('pagehide'));
    bind(this.#document, 'freeze', () => this.revokeNow('freeze'));
    bind(this.#window, 'beforeunload', () => this.revokeNow('beforeunload'));
    bind(this.#window, 'pageshow', (event) => {
      if (event?.persisted !== true) return;
      this.revokeNow('bfcache-restore');
      try { this.#window.location?.reload?.(); } catch { /* remains revoked/logged out */ }
    });
  }

  #detachLifecycle() {
    for (const [target, type, listener] of this.#lifecycle) {
      try { target?.removeEventListener?.(type, listener); } catch { /* best effort */ }
    }
    this.#lifecycle = [];
  }

  #destroyHandle(handle = this.#handle) {
    if (handle === null || handle === undefined) return true;
    this.#ownedHandles.add(handle);
    if (this.#destroyingHandles.has(handle)) return false;
    this.#destroyingHandles.add(handle);
    let destroyed = false;
    try {
      this.#capabilities.destroySdnIdentity(handle);
      destroyed = true;
    } catch {
      destroyed = false;
    } finally {
      this.#destroyingHandles.delete(handle);
    }
    if (!destroyed) return false;
    this.#ownedHandles.delete(handle);
    if (this.#handle === handle) {
      this.#handle = null;
      this.#identity = null;
    }
    return true;
  }

  #retryOwnedHandles() {
    let destroyed = true;
    for (const handle of [...this.#ownedHandles]) {
      if (!this.#destroyHandle(handle)) destroyed = false;
    }
    return destroyed;
  }

  #abortRequests() {
    const controllers = [...this.#controllers];
    this.#controllers.clear();
    for (const controller of controllers) {
      try { controller.abort(); } catch { /* best effort */ }
    }
  }

  #clearSecrets() {
    const buffers = [...this.#secretBuffers];
    this.#secretBuffers.clear();
    for (const bytes of buffers) wipe(bytes);
  }

  #clearCredentialControls() {
    if (this.#credentialControls.size === 0) return;
    const controls = [...this.#credentialControls];
    this.#credentialControls.clear();
    retireCredentialSubtree(this.#document, controls);
  }

  #finishOneShot(handle, generation, {
    allowPublication = false,
    retainIdentity = false,
  } = {}) {
    const current = !this.#destroyed && !this.#revoked
      && this.#generation === generation && this.#handle === handle;
    const ownsHandle = this.#handle === handle || this.#ownedHandles.has(handle);
    if (!current) {
      const destroyed = !ownsHandle || this.#destroyHandle(handle);
      if (!destroyed) {
        this.revokeNow('native-destruction-failed');
        this.#retryOwnedHandles();
      }
      return Object.freeze({ destroyed, permit: null });
    }

    const publicationEpoch = this.#revocationEpoch;
    const candidatePermit = allowPublication ? Object.freeze({}) : null;
    this.#advanceGeneration();
    this.#revoked = true;
    this.#activeTransaction = false;
    this.#publicationPermit = candidatePermit;
    this.#ownedHandles.add(handle);
    this.#handle = null;
    this.#identity = null;
    if (!retainIdentity) this.#retainedIdentity = null;
    const confirmation = this.#confirmation;
    this.#confirmation = null;

    const destroyed = this.#destroyHandle(handle);
    if (!destroyed) {
      this.#publicationPermit = null;
      this.#retainedIdentity = null;
    }
    try { confirmation?.cancel('STALE_CONTROLLER'); } catch { /* terminal state is authoritative */ }
    try { confirmation?.destroy(); } catch { /* terminal state is authoritative */ }
    this.#clearCredentialControls();
    this.#clearSecrets();
    this.#abortRequests();
    if (!destroyed) this.#retryOwnedHandles();
    const permit = destroyed && this.#revocationEpoch === publicationEpoch
      && this.#publicationPermit === candidatePermit
      ? candidatePermit
      : null;
    if (permit === null && this.#publicationPermit === candidatePermit) {
      this.#publicationPermit = null;
    }
    return Object.freeze({ destroyed, permit });
  }

  #assertCurrent(handle, generation) {
    if (this.#destroyed || this.#revoked || this.#generation !== generation
        || this.#handle !== handle) fail('STALE_CONTROLLER');
  }

  #assertGeneration(generation) {
    if (this.#destroyed || this.#revoked || this.#generation !== generation) {
      fail('STALE_CONTROLLER');
    }
  }

  #assertPublicationCurrent(epoch, permit) {
    if (this.#destroyed || this.#revocationEpoch !== epoch
        || permit === null || this.#publicationPermit !== permit) fail('STALE_CONTROLLER');
  }

  #completePendingAccount(event) {
    if (this.#accountPublicationPromise) return this.#accountPublicationPromise;
    const pending = this.#pendingAccountPublication;
    if (!pending || (event !== 'connected' && event !== 'disconnected')) {
      return Promise.reject(new WalletOriginError('STALE_CONTROLLER'));
    }
    this.#pendingAccountPublication = null;
    this.#retainedIdentity = null;

    let resolvePublication;
    let rejectPublication;
    const stablePromise = new Promise((resolve, reject) => {
      resolvePublication = resolve;
      rejectPublication = reject;
    });
    this.#accountPublicationPromise = stablePromise;
    void (async () => {
      const publicationController = abortController(this.#window);
      if (publicationController) this.#controllers.add(publicationController);
      try {
        this.#assertPublicationCurrent(pending.epoch, pending.permit);
        assertWalletContext({ document: this.#document, window: this.#window });
        if (typeof this.#relay?.publishResult !== 'function') fail('RELAY_UNAVAILABLE');
        const result = event === 'connected' ? pending.connectedResult : disconnectedAccountResult();
        let publication;
        try {
          publication = await this.#relay.publishResult(pending.transaction, result, {
            signal: publicationController?.signal,
          });
        } catch (error) {
          this.#assertPublicationCurrent(pending.epoch, pending.permit);
          throw error;
        }
        this.#assertPublicationCurrent(pending.epoch, pending.permit);
        assertWalletContext({ document: this.#document, window: this.#window });
        if (typeof this.#relay?.navigate === 'function') {
          const completion = validateWalletRelayCompletion(pending.transaction, publication);
          this.#assertPublicationCurrent(pending.epoch, pending.permit);
          this.#publicationPermit = null;
          this.#relay.navigate(completion.redirectUri);
        } else {
          this.#publicationPermit = null;
        }
        resolvePublication(publication);
      } catch (error) {
        if (this.#publicationPermit === pending.permit) this.#publicationPermit = null;
        try { this.#relay?.revokeNow?.('account-publication-failed'); } catch { /* no callback remains approved */ }
        rejectPublication(error);
      } finally {
        if (publicationController) this.#controllers.delete(publicationController);
      }
    })();
    return stablePromise;
  }

  registerCredentialControls({ usernameControl, passwordControl }) {
    if (this.#destroyed || this.#revoked) fail('STALE_CONTROLLER');
    if (!usernameControl || !passwordControl) fail('INVALID_CREDENTIAL_FORM');
    this.#credentialControls.add(usernameControl);
    this.#credentialControls.add(passwordControl);
  }

  copyPublicIdentity() {
    const identity = this.#identity ?? this.#retainedIdentity;
    if (!identity) fail('STALE_CONTROLLER');
    try { return copyModernPublicIdentity(identity); } catch { fail('WASM_FAILURE'); }
  }

  async unlockPassword({ usernameControl, passwordControl, accountIndex = 0 }) {
    if (this.#destroyed || this.#revoked) fail('STALE_CONTROLLER');
    if (accountIndex !== 0) fail('INVALID_ACCOUNT');
    this.registerCredentialControls({ passwordControl, usernameControl });
    try {
      assertWalletContext({ document: this.#document, window: this.#window });
    } catch (error) {
      this.#clearCredentialControls();
      rethrowContextError(error);
    }
    this.#advanceGeneration();
    const generation = this.#generation;
    if (!this.#destroyHandle()) {
      this.#clearCredentialControls();
      this.revokeNow('native-destruction-failed');
      fail('DESTRUCTION_FAILED');
    }
    this.#retainedIdentity = null;
    let usernameUtf8;
    let passwordUtf8;
    try {
      try {
        assertWalletContext({ document: this.#document, window: this.#window });
      } catch (error) {
        rethrowContextError(error);
      }
      this.#assertGeneration(generation);
      const username = usernameControl?.value;
      const password = passwordControl?.value;
      if (!isWellFormed(username)) fail('INVALID_USERNAME');
      if (!isWellFormed(password)) fail('INVALID_PASSWORD');
      usernameUtf8 = encoder.encode(username);
      passwordUtf8 = encoder.encode(password);
      this.#secretBuffers.add(usernameUtf8);
      this.#secretBuffers.add(passwordUtf8);
    } finally {
      this.#clearCredentialControls();
    }

    let derived;
    try {
      derived = await this.#capabilities.derivePasswordIdentity({
        accountIndex,
        passwordUtf8,
        usernameUtf8,
      });
      if (!derived || typeof derived !== 'object') {
        fail('WASM_FAILURE');
      }
      const handle = derived.handle;
      if (handle === null || handle === undefined) fail('WASM_FAILURE');
      this.#ownedHandles.add(handle);
      let identity;
      try {
        identity = copyModernPublicIdentity(derived.identity);
      } catch {
        const destroyed = this.#destroyHandle(handle);
        derived = null;
        if (!destroyed) {
          this.revokeNow('native-destruction-failed');
          fail('DESTRUCTION_FAILED');
        }
        fail('WASM_FAILURE');
      }
      if (this.#destroyed || this.#revoked || this.#generation !== generation) {
        const destroyed = this.#destroyHandle(handle);
        if (!destroyed) {
          this.revokeNow('native-destruction-failed');
          fail('DESTRUCTION_FAILED');
        }
        fail('STALE_CONTROLLER');
      }
      this.#handle = handle;
      this.#identity = identity;
      return identity;
    } finally {
      wipe(usernameUtf8);
      wipe(passwordUtf8);
      this.#secretBuffers.delete(usernameUtf8);
      this.#secretBuffers.delete(passwordUtf8);
    }
  }

  async unlockLegacy({
    accountIndex = 0,
    mnemonicControl = null,
    operation,
    passwordControl = null,
    profile,
    usernameControl = null,
  }) {
    if (this.#destroyed || this.#revoked) fail('STALE_CONTROLLER');
    if (operation !== 'sdn.auth.raw-challenge.v1') fail('OPERATION_NOT_ALLOWED');
    if (accountIndex !== 0) fail('INVALID_ACCOUNT');
    const fastPassword = profile === 'password-fast-v1-legacy';
    const mnemonic = profile === 'bip39-mnemonic-v1-legacy';
    if (!fastPassword && !mnemonic) fail('INVALID_LEGACY_PROFILE');
    if (fastPassword) {
      this.registerCredentialControls({ passwordControl, usernameControl });
    } else {
      if (!mnemonicControl || typeof mnemonicControl !== 'object') fail('INVALID_CREDENTIAL_FORM');
      this.#credentialControls.add(mnemonicControl);
    }
    try {
      assertWalletContext({ document: this.#document, window: this.#window });
    } catch (error) {
      this.#clearCredentialControls();
      rethrowContextError(error);
    }
    this.#advanceGeneration();
    const generation = this.#generation;
    if (!this.#destroyHandle()) {
      this.#clearCredentialControls();
      this.revokeNow('native-destruction-failed');
      fail('DESTRUCTION_FAILED');
    }
    this.#retainedIdentity = null;
    let usernameUtf8;
    let passwordUtf8;
    let mnemonicUtf8;
    try {
      try {
        assertWalletContext({ document: this.#document, window: this.#window });
      } catch (error) {
        rethrowContextError(error);
      }
      this.#assertGeneration(generation);
      if (fastPassword) {
        const username = usernameControl?.value;
        const password = passwordControl?.value;
        if (!isWellFormed(username)) fail('INVALID_USERNAME');
        if (!isWellFormed(password)) fail('INVALID_PASSWORD');
        usernameUtf8 = encoder.encode(username);
        passwordUtf8 = encoder.encode(password);
        this.#secretBuffers.add(usernameUtf8);
        this.#secretBuffers.add(passwordUtf8);
      } else {
        const mnemonicValue = mnemonicControl?.value;
        if (!isWellFormed(mnemonicValue)) fail('INVALID_MNEMONIC');
        mnemonicUtf8 = encoder.encode(mnemonicValue);
        this.#secretBuffers.add(mnemonicUtf8);
      }
    } finally {
      this.#clearCredentialControls();
    }

    let derived;
    try {
      derived = fastPassword
        ? await this.#capabilities.deriveLegacyPasswordIdentity({
          accountIndex,
          passwordUtf8,
          usernameUtf8,
        })
        : await this.#capabilities.importLegacyMnemonicIdentity({ accountIndex, mnemonicUtf8 });
      if (!derived || typeof derived !== 'object') fail('WASM_FAILURE');
      const handle = derived.handle;
      if (handle === null || handle === undefined) fail('WASM_FAILURE');
      this.#ownedHandles.add(handle);
      let identity;
      try {
        identity = copyLegacyPublicIdentity(derived.identity, { accountIndex, profile });
      } catch {
        const destroyed = this.#destroyHandle(handle);
        derived = null;
        if (!destroyed) {
          this.revokeNow('native-destruction-failed');
          fail('DESTRUCTION_FAILED');
        }
        fail('WASM_FAILURE');
      }
      if (this.#destroyed || this.#revoked || this.#generation !== generation) {
        const destroyed = this.#destroyHandle(handle);
        if (!destroyed) {
          this.revokeNow('native-destruction-failed');
          fail('DESTRUCTION_FAILED');
        }
        fail('STALE_CONTROLLER');
      }
      this.#handle = handle;
      this.#identity = identity;
      return identity;
    } finally {
      wipe(usernameUtf8);
      wipe(passwordUtf8);
      wipe(mnemonicUtf8);
      this.#secretBuffers.delete(usernameUtf8);
      this.#secretBuffers.delete(passwordUtf8);
      this.#secretBuffers.delete(mnemonicUtf8);
    }
  }

  async prepare(transactionReference) {
    if (this.#destroyed || this.#revoked) fail('STALE_CONTROLLER');
    if (this.#activeTransaction) fail('TRANSACTION_IN_PROGRESS');
    this.#activeTransaction = true;
    const generation = this.#generation;
    const expectedTransactionId = typeof transactionReference === 'string'
      ? transactionReference
      : transactionReference?.transactionId ?? null;
    const requestController = abortController(this.#window);
    if (requestController) this.#controllers.add(requestController);
    try {
      const fetched = typeof this.#relay?.fetchTransaction === 'function'
        ? await this.#relay.fetchTransaction(transactionReference, { signal: requestController?.signal })
        : transactionReference;
      this.#assertGeneration(generation);
      const validated = await validateWalletTransaction(fetched, {
        expectedTransactionId,
        registry: this.#registry,
        relay: this.#relay,
        sha256: this.#sha256,
        window: this.#window,
      });
      this.#assertGeneration(generation);
      assertWalletContext({ document: this.#document, window: this.#window });
      this.#prepared.add(validated);
      if (requestController) this.#preparedControllers.set(validated, requestController);
      return validated;
    } catch (error) {
      const stale = this.#destroyed || this.#revoked || this.#generation !== generation;
      this.#activeTransaction = false;
      if (requestController) this.#controllers.delete(requestController);
      if (stale) fail('STALE_CONTROLLER');
      if (error instanceof WalletOriginError) throw error;
      if (error instanceof WalletOperationError) throw new WalletOriginError(error.code);
      throw error;
    }
  }

  async executePrepared(prepared) {
    if (!prepared || typeof prepared !== 'object' || !this.#prepared.has(prepared)) {
      fail('INVALID_TRANSACTION');
    }
    this.#prepared.delete(prepared);
    const requestController = this.#preparedControllers.get(prepared) ?? null;
    this.#preparedControllers.delete(prepared);
    if (this.#destroyed || this.#revoked || this.#handle === null) {
      if (requestController) this.#controllers.delete(requestController);
      this.#activeTransaction = false;
      fail('STALE_CONTROLLER');
    }
    const handle = this.#handle;
    const identity = this.#identity;
    const generation = this.#generation;
    let finished = false;
    try {
      this.#assertCurrent(handle, generation);
      let validated = await validateWalletTransaction(prepared.transaction, {
        expectedTransactionId: prepared.transaction.transactionId,
        registry: this.#registry,
        relay: this.#relay,
        sha256: this.#sha256,
        window: this.#window,
      });
      this.#assertCurrent(handle, generation);
      assertWalletContext({ document: this.#document, window: this.#window });
      this.#confirmation = requestTrustedConfirmation({
        binding: validated.binding,
        document: this.#document,
        identity,
        request: validated.request,
        transaction: validated.transaction,
      });
      await this.#confirmation.promise;
      this.#assertCurrent(handle, generation);
      assertWalletContext({ document: this.#document, window: this.#window });
      validated = await validateWalletTransaction(prepared.transaction, {
        expectedTransactionId: prepared.transaction.transactionId,
        registry: this.#registry,
        relay: this.#relay,
        sha256: this.#sha256,
        window: this.#window,
      });
      this.#assertCurrent(handle, generation);
      assertWalletContext({ document: this.#document, window: this.#window });
      const result = await executeWalletOperation({
        assertCurrent: () => this.#assertCurrent(handle, generation),
        binding: validated.binding,
        handle,
        identity,
        transaction: validated.transaction,
        wasm: this.#capabilities,
      });
      this.#assertCurrent(handle, generation);
      assertWalletContext({ document: this.#document, window: this.#window });
      const retainIdentity = validated.transaction.operation === 'sdn.wallet.account.v1';
      if (retainIdentity) this.#retainedIdentity = copyModernPublicIdentity(identity);
      const retirement = this.#finishOneShot(handle, generation, {
        allowPublication: true,
        retainIdentity,
      });
      finished = true;
      if (!retirement.destroyed) {
        this.#retainedIdentity = null;
        fail('DESTRUCTION_FAILED');
      }
      const publicationEpoch = this.#revocationEpoch;
      const publicationPermit = retirement.permit;
      if (retainIdentity) {
        this.#assertPublicationCurrent(publicationEpoch, publicationPermit);
        this.#pendingAccountPublication = Object.freeze({
          connectedResult: result,
          epoch: publicationEpoch,
          permit: publicationPermit,
          transaction: validated.transaction,
        });
        return Object.freeze({ accountReady: true });
      }
      try {
        this.#assertPublicationCurrent(publicationEpoch, publicationPermit);
        if (typeof this.#relay?.publishResult !== 'function') fail('RELAY_UNAVAILABLE');
        const publicationController = abortController(this.#window);
        if (publicationController) this.#controllers.add(publicationController);
        let publication;
        try {
          try {
            publication = await this.#relay.publishResult(validated.transaction, result, {
              signal: publicationController?.signal,
            });
          } catch (error) {
            this.#assertPublicationCurrent(publicationEpoch, publicationPermit);
            throw error;
          }
        } finally {
          if (publicationController) this.#controllers.delete(publicationController);
        }
        this.#assertPublicationCurrent(publicationEpoch, publicationPermit);
        assertWalletContext({ document: this.#document, window: this.#window });
        if (typeof this.#relay?.navigate === 'function') {
          const completion = validateWalletRelayCompletion(validated.transaction, publication);
          this.#assertPublicationCurrent(publicationEpoch, publicationPermit);
          this.#publicationPermit = null;
          this.#relay.navigate(completion.redirectUri);
        } else {
          this.#publicationPermit = null;
        }
        return publication;
      } finally {
        if (this.#publicationPermit === publicationPermit) this.#publicationPermit = null;
      }
    } catch (error) {
      if (!finished && (this.#generation !== generation || this.#handle !== handle)) {
        fail('STALE_CONTROLLER');
      }
      if (error instanceof WalletOriginError) throw error;
      if (error instanceof WalletOperationError) throw new WalletOriginError(error.code);
      throw error;
    } finally {
      if (requestController) this.#controllers.delete(requestController);
      if (!finished) this.#finishOneShot(handle, generation);
    }
  }

  async execute(transactionReference) {
    if (this.#destroyed || this.#revoked || this.#handle === null) fail('STALE_CONTROLLER');
    const handle = this.#handle;
    const generation = this.#generation;
    try {
      const prepared = await this.prepare(transactionReference);
      return await this.executePrepared(prepared);
    } catch (error) {
      if (!this.#revoked && this.#handle === handle) this.#finishOneShot(handle, generation);
      throw error;
    }
  }

  async logout() {
    if (this.#pendingAccountPublication || this.#accountPublicationPromise) {
      return this.#completePendingAccount('disconnected');
    }
    this.revokeNow('logout');
    this.#retainedIdentity = null;
  }

  returnToSite() {
    return this.#completePendingAccount('connected');
  }

  revokeNow(reason) {
    this.#revocationEpoch = this.#revocationEpoch >= Number.MAX_SAFE_INTEGER
      ? 1
      : this.#revocationEpoch + 1;
    this.#publicationPermit = null;
    this.#pendingAccountPublication = null;
    if (this.#destroyed) {
      this.#retryOwnedHandles();
      return;
    }
    const newlyRevoked = !this.#revoked;
    if (newlyRevoked) {
      this.#revoked = true;
      this.#advanceGeneration();
    }
    this.#activeTransaction = false;
    this.#retainedIdentity = null;
    if (this.#handle !== null && this.#handle !== undefined) {
      this.#ownedHandles.add(this.#handle);
    }
    this.#handle = null;
    this.#identity = null;
    const confirmation = this.#confirmation;
    this.#confirmation = null;
    const notifyRelay = !this.#relayRevoked;
    if (notifyRelay) this.#relayRevoked = true;

    try { confirmation?.cancel('STALE_CONTROLLER'); } catch { /* terminal state is authoritative */ }
    try { confirmation?.destroy(); } catch { /* terminal state is authoritative */ }
    this.#clearCredentialControls();
    this.#clearSecrets();
    this.#abortRequests();
    this.#retryOwnedHandles();
    if (notifyRelay) {
      try { this.#relay?.revokeNow?.(reason); } catch { /* synchronous local revocation remains complete */ }
    }
  }

  destroy(reason = 'destroy') {
    if (this.#destroyPromise) {
      this.#retryOwnedHandles();
      return this.#destroyPromise;
    }
    let resolveDestroy;
    const stablePromise = new Promise((resolve) => { resolveDestroy = resolve; });
    this.#destroyPromise = stablePromise;
    void (async () => {
      try {
        this.revokeNow(reason);
        this.#destroyed = true;
        this.#detachLifecycle();
        try { await this.#relay?.destroy?.(reason); } catch { /* best-effort remote cleanup */ }
      } finally {
        resolveDestroy();
      }
    })();
    return stablePromise;
  }
}
