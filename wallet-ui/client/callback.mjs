const SAFE_RETRY_MESSAGE = 'Wallet return could not be completed. Close this page and try Login again.';
const CALLBACK_FRAGMENT = /^#code=([0-9a-f]{64})&state=([0-9a-f]{64})$/u;

function failClosed() {
  throw new Error(SAFE_RETRY_MESSAGE);
}

export function completeWalletCallbackV1(location, storage, history, close) {
  let fragment;
  try {
    fragment = location.hash;
    const pathname = typeof location.pathname === 'string' && location.pathname.startsWith('/')
      ? location.pathname
      : '/';
    const search = typeof location.search === 'string' && location.search.startsWith('?')
      ? location.search
      : '';
    history.replaceState(null, '', `${pathname}${search}`);
  } catch {
    failClosed();
  }

  const match = CALLBACK_FRAGMENT.exec(fragment);
  if (!match) failClosed();
  const [, code, state] = match;
  const expiresAt = new Date(Date.now() + 120_000).toISOString();
  const key = `sdn.wallet.callback.v1:${state}`;
  const value = JSON.stringify({ schemaVersion: 1, code, state, expiresAt });

  try {
    storage.setItem(key, value);
  } catch {
    failClosed();
  }

  try {
    close();
  } catch {
    // The bounded public callback record is complete even if browser close is denied.
  }
}
