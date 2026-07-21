import { createWalletClient } from './index.mjs';

const GLOBAL_NAME = 'SDNWalletPublicClient';

if (Object.prototype.hasOwnProperty.call(globalThis, GLOBAL_NAME)) {
  throw new Error('SDN wallet public client global already exists');
}

function create(options) {
  if (arguments.length !== 1) return createWalletClient(...arguments);
  return createWalletClient(options);
}

const namespace = Object.freeze({ create });

Object.defineProperty(globalThis, GLOBAL_NAME, {
  configurable: false,
  enumerable: false,
  value: namespace,
  writable: false,
});
