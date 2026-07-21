import type {
  AssetReviewWalletClient,
  WalletClientErrorMessages,
} from './types.js';

export declare const WALLET_CLIENT_ERRORS: WalletClientErrorMessages;

export declare function createAssetReviewWalletClient(): AssetReviewWalletClient;
