import {
  buildAssetReviewAuthorityActivationRequest,
  buildAssetReviewAuthorityActivationResult,
  buildAssetReviewDecisionRequest,
  buildAssetReviewDecisionResult,
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

const REVIEW_ADAPTERS = Object.freeze({
  ...BASE_ADAPTERS,
  assetReviewApproval: Object.freeze({
    buildRequest: buildAssetReviewDecisionRequest,
    kind: 'typed',
    operation: 'sdn.asset-review.decision.v1',
    parseResult: buildAssetReviewDecisionResult,
  }),
  authorityActivation: Object.freeze({
    buildRequest: buildAssetReviewAuthorityActivationRequest,
    kind: 'typed',
    operation: 'sdn.asset-review.authority-activation.v1',
    parseResult: buildAssetReviewAuthorityActivationResult,
  }),
});

export function createAssetReviewWalletClient() {
  if (arguments.length !== 0) throw walletClientError('INVALID_REQUEST');
  const core = createInternalWalletClient({
    adapters: REVIEW_ADAPTERS,
    clientId: 'sdn-asset-review-v1',
  });
  return createPublicApi(core, {
    requestAssetReviewApproval: 'assetReviewApproval',
    requestAuthorityActivation: 'authorityActivation',
  });
}
