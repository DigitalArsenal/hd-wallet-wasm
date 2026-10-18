import type {
  CreateWalletClientOptions,
  FlatbuffersWalletClient,
  FlatsqlWalletClient,
  WalletClientErrorMessages,
  WalletPublicClient,
} from './types.js';

export declare const WALLET_CLIENT_ERRORS: WalletClientErrorMessages;

export declare function createWalletClient(
  options: { readonly clientId: 'sdn-flatbuffers-pages-v1' },
): FlatbuffersWalletClient;
export declare function createWalletClient(
  options: { readonly clientId: 'sdn-flatsql-pages-v1' },
): FlatsqlWalletClient;
export declare function createWalletClient(
  options: CreateWalletClientOptions,
): WalletPublicClient;
