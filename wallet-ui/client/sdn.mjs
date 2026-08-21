import {
  buildSdnLoginV1Request,
  buildSdnLoginV1Result,
  buildSdnLoginV2Request,
  buildSdnLoginV2Result,
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

export { WALLET_CLIENT_ERRORS };

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

const SDN_ADAPTERS = Object.freeze({
  ...BASE_ADAPTERS,
  sdnLoginV1: Object.freeze({
    buildRequest: buildSdnLoginV1Request,
    kind: 'typed',
    operation: 'sdn.auth.raw-challenge.v1',
    parseResult: buildSdnLoginV1Result,
  }),
  sdnLoginV2: Object.freeze({
    buildRequest: buildSdnLoginV2Request,
    kind: 'typed',
    operation: 'sdn.auth.jcs-envelope.v2',
    parseResult: buildSdnLoginV2Result,
  }),
});

export function createSdnWalletClient() {
  if (arguments.length !== 0) throw walletClientError('INVALID_REQUEST');
  const core = createInternalWalletClient({
    adapters: SDN_ADAPTERS,
    clientId: 'sdn-node-console-v1',
  });
  return createPublicApi(core, {
    requestSdnLoginV1: 'sdnLoginV1',
    requestSdnLoginV2: 'sdnLoginV2',
  });
}
