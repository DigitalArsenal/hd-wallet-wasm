import type {
  SdnWalletClient,
  SpaceAwarePublishWalletClient,
  WalletClientErrorMessages,
} from './types.js';

export declare const WALLET_CLIENT_ERRORS: WalletClientErrorMessages;

export declare function createSdnWalletClient(): SdnWalletClient;
export declare function createSpaceAwarePublishWalletClient(): SpaceAwarePublishWalletClient;
