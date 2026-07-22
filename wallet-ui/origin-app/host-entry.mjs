import initHDWallet from 'hd-wallet-wasm';

import { mountWalletOriginApp } from './app.mjs';
import './host.css';

const mount = document.querySelector('[data-wallet-origin-root]') ?? document.body;

async function startWalletOrigin() {
  if (window.top !== window) throw new Error('Wallet origin cannot run in a frame');
  const styleSentinel = getComputedStyle(document.documentElement)
    .getPropertyValue('--sdn-wallet-origin-style-ready').trim();
  if (styleSentinel !== '"2.0.24"') throw new Error('Wallet origin style integrity failed');
  const wasm = await initHDWallet();
  await mountWalletOriginApp({ document, mount, wasm, window });
}

void startWalletOrigin().catch(() => {
  if (mount.childElementCount === 1
      && mount.firstElementChild?.classList?.contains('wallet-terminal-error') === true) {
    return;
  }
  const message = document.createElement('p');
  message.className = 'wallet-error';
  message.textContent = 'The wallet could not start. Close this window and try again.';
  mount.replaceChildren(message);
});
