import type {
  CreateWalletClientOptions,
  WalletClientErrorMessages,
  WalletPublicClient,
} from './types.js';

export declare const WALLET_CLIENT_ERRORS: WalletClientErrorMessages;

export declare function createWalletClient(
  options: CreateWalletClientOptions,
): WalletPublicClient;
