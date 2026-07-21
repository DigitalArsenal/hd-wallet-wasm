import {
  buildWalletAccountRequest,
  buildWalletAccountResult,
  buildWalletConnectRequest,
  buildWalletConnectResult,
} from './wire.mjs';
import {
  createInternalWalletClient,
  createPublicApi,
  walletClientError,
  WALLET_CLIENT_ERRORS,
} from './relay-client.mjs';

const CLIENT_IDS = Object.freeze([
  'orbpro-pages-v1',
  'sdn-asset-models-pages-v1',
  'sdn-asset-review-v1',
  'sdn-flatbuffers-pages-v1',
  'sdn-flatsql-pages-v1',
  'sdn-landing-web-v1',
  'sdn-module-sdk-pages-v1',
  'sdn-node-console-v1',
  'sdn-standards-web-v1',
  'spaceaware-web-v1',
]);

export { WALLET_CLIENT_ERRORS };

function validateWalletClientOptions(options) {
  let descriptor;
  try {
    const keys = Reflect.ownKeys(options);
    if (options === null || typeof options !== 'object' || Array.isArray(options)
        || Object.getPrototypeOf(options) !== Object.prototype
        || keys.length !== 1 || keys[0] !== 'clientId') {
      throw walletClientError('INVALID_REQUEST');
    }
    descriptor = Object.getOwnPropertyDescriptor(options, 'clientId');
  } catch {
    throw walletClientError('INVALID_REQUEST');
  }
  if (!descriptor?.enumerable || !('value' in descriptor)
      || typeof descriptor.value !== 'string') {
    throw walletClientError('INVALID_REQUEST');
  }
  if (!CLIENT_IDS.includes(descriptor.value)) throw walletClientError('INVALID_CLIENT');
  return descriptor.value;
}

const BASE_ADAPTERS = Object.freeze({
  account: Object.freeze({
    buildRequest: () => buildWalletAccountRequest({}),
    kind: 'account',
    operation: 'sdn.wallet.account.v1',
    parseResult: buildWalletAccountResult,
  }),
  connect: Object.freeze({
    buildRequest: () => buildWalletConnectRequest({}),
    kind: 'connect',
    operation: 'sdn.wallet.connect.v1',
    parseResult: buildWalletConnectResult,
  }),
});

export function createWalletClient(options) {
  if (arguments.length !== 1) throw walletClientError('INVALID_REQUEST');
  const clientId = validateWalletClientOptions(options);
  const core = createInternalWalletClient({ adapters: BASE_ADAPTERS, clientId });
  return createPublicApi(core);
}
