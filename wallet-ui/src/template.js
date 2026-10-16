export function getModalHTML() {
  return `
  <!-- Account view: a full-width page panel under the SDN header (account-view.js) -->
  <div id="account-view" class="account-view" role="region" aria-label="Account" hidden>
    <p id="account-live" class="account-live" role="status" aria-live="polite"></p>
    <div class="account-identity-bar">
      <div class="account-identity-inner">
        <div id="account-avatar" class="account-avatar is-mark" aria-hidden="true"><span class="avatar-mark"></span></div>
        <div class="account-identity-text">
          <div class="account-name-line"><span id="account-name" class="account-name"></span><button id="account-add-name" class="link-btn" type="button" hidden>Add your name</button></div>
          <div class="account-peer-line"><span id="account-peer-id" class="account-peer-id"></span><button id="account-copy-peer" class="copy-chip" type="button">Copy</button></div>
        </div>
        <span id="account-status" class="account-status"></span>
        <button id="account-close" class="btn btn-icon account-close" type="button" aria-label="Close"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>
    </div>
    <div class="account-tabs">
      <div class="account-tabs-inner" role="tablist" aria-label="Account sections">
        <button id="account-tab-profile" class="account-tab" type="button" role="tab" aria-selected="true" aria-controls="account-pane-profile" data-section="profile">Profile</button>
        <button id="account-tab-messages" class="account-tab" type="button" role="tab" aria-selected="false" aria-controls="account-pane-messages" data-section="messages" tabindex="-1">Messages</button>
        <button id="account-tab-people" class="account-tab" type="button" role="tab" aria-selected="false" aria-controls="account-pane-people" data-section="people" tabindex="-1">People</button>
        <button id="account-tab-assets" class="account-tab" type="button" role="tab" aria-selected="false" aria-controls="account-pane-assets" data-section="assets" tabindex="-1">Assets</button>
        <button id="account-tab-settings" class="account-tab" type="button" role="tab" aria-selected="false" aria-controls="account-pane-settings" data-section="settings" tabindex="-1">Settings</button>
      </div>
    </div>
    <section id="account-pane-profile" class="account-pane" role="tabpanel" aria-labelledby="account-tab-profile"></section>
    <section id="account-pane-messages" class="account-pane" role="tabpanel" aria-labelledby="account-tab-messages" hidden></section>
    <section id="account-pane-people" class="account-pane" role="tabpanel" aria-labelledby="account-tab-people" hidden></section>
    <section id="account-pane-assets" class="account-pane" role="tabpanel" aria-labelledby="account-tab-assets" hidden></section>
    <section id="account-pane-settings" class="account-pane" role="tabpanel" aria-labelledby="account-tab-settings" hidden></section>
  </div>

  <!-- Login Modal -->
  <div id="login-modal" class="modal">
    <div class="modal-glass login-modal-content">
      <div class="modal-header"><h3>Login</h3><button class="modal-close" type="button" aria-label="Close"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
      <div class="modal-body">
        <div class="method-tabs">
          <button class="method-tab active" data-method="external">External Wallet</button>
          <button class="method-tab" data-method="password">Password</button>
          <button class="method-tab" data-method="seed">Seed Phrase</button>
        </div>
        <div id="external-method" class="method-content active">
          <div id="external-wallet-mount"></div>
        </div>
        <form id="password-method" class="method-content" novalidate>
          <div class="glass-input-group"><input type="text" id="wallet-username" class="glass-input" placeholder="Username" autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="Username"></div>
          <div class="glass-input-group">
            <div class="password-input-wrap"><input type="password" id="wallet-password" class="glass-input" placeholder="Password" autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="Password" aria-describedby="password-feedback password-note"><button type="button" id="toggle-password-vis" class="password-toggle" title="Show password" aria-label="Show password"><svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
            <div class="entropy-bar"><div class="entropy-fill" id="strength-fill"></div><div class="entropy-threshold"></div></div>
            <span class="entropy-label"><span id="entropy-bits">0</span> bits, estimated</span>
            <p id="password-feedback" class="password-feedback" role="status" aria-live="polite"></p>
          </div>
          <button id="derive-from-password" class="glass-btn primary full-width" disabled type="button">Sign in</button>
          <p id="password-note" class="password-note">A password wallet is only as strong as its password: anyone who guesses your username and password can take the funds, and there is no recovery. Passwords are stretched with scrypt (memory-hard) and must reach an estimated 10<sup>20</sup> guesses &mdash; for example five or more uncommon random words.</p>
          <details class="legacy-password">
            <summary>Made your wallet with a password before version 3.0?</summary>
            <p>Wallets made with the old password method used a fast hash that computers can guess quickly. Enter the same username and password above and open your old wallet <strong>read-only</strong>. Then, in Assets, choose a new password and move your funds to the new wallet. Your old wallet keeps opening this way, so its funds stay reachable.</p>
            <button id="derive-from-legacy-password" class="glass-btn full-width" type="button" disabled>Sign in with old password method</button>
          </details>
        </form>
        <div id="seed-method" class="method-content">
          <div class="glass-input-group seed-entry">
            <p class="seed-hint" id="seed-hint">Type or paste a 12&ndash;24 word recovery phrase. Pasting into any field fills them all.</p>
            <div id="seed-phrase" class="seed-slots" role="group" aria-labelledby="seed-hint"></div>
            <div class="seed-actions"><button id="generate-seed" class="glass-btn small" type="button">Generate</button><button id="validate-seed" class="glass-btn small" type="button" aria-live="polite">Validate</button><button id="toggle-seed-vis" class="glass-btn small" type="button" aria-pressed="false" aria-controls="seed-phrase">Show words</button></div>
          </div>
          <button id="derive-from-seed" class="glass-btn primary full-width" type="button" disabled>Login</button>
        </div>
        <div id="legacy-wallet-quarantine" class="stored-wallet-info">
          <p>Legacy saved-wallet data is quarantined and will not be unlocked automatically.</p>
          <div id="legacy-wallet-quarantine-list"></div>
          <span id="legacy-wallet-quarantine-status" class="stored-wallet-date" aria-live="polite"></span>
        </div>
      </div>
      <div id="wallet-info-box" class="wallet-info-box wallet-info-footer">
        <div id="wallet-info-expanded" class="wallet-info-expanded"><div class="wallet-info-content"><strong>Decentralized Wallet</strong> — Your credentials never leave your browser.</div><button class="wallet-info-close" id="wallet-info-dismiss" title="Dismiss" aria-label="Dismiss"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
        <div id="wallet-info-collapsed" class="wallet-info-collapsed"><span>Decentralized Wallet</span><div class="wallet-info-icon-wrap"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="0.75"/><text x="8" y="8" text-anchor="middle" dominant-baseline="central" font-size="11" fill="currentColor">i</text></svg></div></div>
      </div>
    </div>
  </div>

  <!-- Loading Overlay -->
  <div id="loading-overlay" class="loading-overlay">
    <div class="loading-spinner"></div>
    <span id="status">Loading WASM modules...</span>
  </div>`;
}
