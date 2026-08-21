import { completeWalletCallbackV1 } from './callback.mjs';

const SAFE_RETRY_MESSAGE = 'Wallet return could not be completed. Close this page and try Login again.';

function renderSafeRetry() {
  if (window.document?.body) window.document.body.textContent = SAFE_RETRY_MESSAGE;
}

function clearFragment() {
  const pathname = typeof window.location?.pathname === 'string'
    && window.location.pathname.startsWith('/')
    ? window.location.pathname
    : '/';
  const search = typeof window.location?.search === 'string'
    && window.location.search.startsWith('?')
    ? window.location.search
    : '';
  window.history.replaceState(null, '', `${pathname}${search}`);
}

if (window.top !== window) {
  try {
    clearFragment();
  } catch {
    // The safe terminal message remains the only rendered value.
  }
  renderSafeRetry();
} else {
  let closeInvoked = false;
  const closeOnce = () => {
    if (closeInvoked) return;
    closeInvoked = true;
    try {
      window.close();
    } catch {
      // Browser close is best effort after the callback record is complete.
    }
  };
  try {
    const lazyStorage = {
      setItem(key, value) {
        window.localStorage.setItem(key, value);
      },
    };
    completeWalletCallbackV1(
      window.location,
      lazyStorage,
      window.history,
      closeOnce,
    );
  } catch {
    renderSafeRetry();
  }
}
