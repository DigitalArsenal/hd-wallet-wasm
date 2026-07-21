import {
  createWalletClient,
  WALLET_CLIENT_ERRORS as baseErrors,
} from 'hd-wallet-ui/client';
import {
  createSdnWalletClient,
  WALLET_CLIENT_ERRORS as sdnErrors,
} from 'hd-wallet-ui/client/sdn';
import {
  createAssetReviewWalletClient,
  WALLET_CLIENT_ERRORS as reviewErrors,
} from 'hd-wallet-ui/client/asset-review';
import { completeWalletCallbackV1 } from 'hd-wallet-ui/client/callback';

const base = createWalletClient({ clientId: 'sdn-landing-web-v1' });
const sdn = createSdnWalletClient();
const review = createAssetReviewWalletClient();

void base.connect();
void sdn.requestSdnLoginV1({ challenge: new Uint8Array(32), protocolVersion: 1 });
void review.requestAssetReviewApproval({
  audience: 'asset-review:assets.ipfs.01',
  candidateKey: `asset-review:provider/model:${'a'.repeat(64)}`,
  challengeId: 'b'.repeat(64),
  clientId: 'sdn-asset-review-v1',
  decision: 'disapprove',
  expiresAt: '2026-07-21T12:05:00.000Z',
  issuedAt: '2026-07-21T12:00:00.000Z',
  metadataSha256: 'c'.repeat(64),
  modelBytes: 1,
  modelCid: 'bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  modelSha256: 'd'.repeat(64),
  nonce: 'e'.repeat(64),
  previousDecisionHead: null,
  protocolVersion: 1,
  reason: 'fixture',
  requestOrigin: 'https://review.spacedatanetwork.org',
});

completeWalletCallbackV1(
  { hash: `#code=${'a'.repeat(64)}&state=${'b'.repeat(64)}`, pathname: '/callback', search: '' },
  { setItem(_key: string, _value: string) {} },
  { replaceState(_data: unknown, _unused: string, _url?: string) {} },
  () => {},
);
completeWalletCallbackV1(
  window.location,
  window.localStorage,
  window.history,
  window.close.bind(window),
);

baseErrors.INVALID_REQUEST satisfies string;
sdnErrors.INVALID_REQUEST satisfies string;
reviewErrors.INVALID_REQUEST satisfies string;

// @ts-expect-error the base client entry must not claim the purpose-specific SDN factory.
import { createSdnWalletClient as invalidBaseExport } from 'hd-wallet-ui/client';
// @ts-expect-error the SDN client entry must not claim the asset-review factory.
import { createAssetReviewWalletClient as invalidSdnExport } from 'hd-wallet-ui/client/sdn';
// @ts-expect-error the asset-review entry must not claim the generic factory.
import { createWalletClient as invalidReviewExport } from 'hd-wallet-ui/client/asset-review';
// @ts-expect-error the callback entry must not claim a wallet-client factory.
import { createWalletClient as invalidCallbackExport } from 'hd-wallet-ui/client/callback';

void [invalidBaseExport, invalidSdnExport, invalidReviewExport, invalidCallbackExport];
