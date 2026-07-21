import type {
  WalletCallbackClose,
  WalletCallbackHistory,
  WalletCallbackLocation,
  WalletCallbackStorage,
} from './types.js';

export declare function completeWalletCallbackV1(
  location: WalletCallbackLocation,
  storage: WalletCallbackStorage,
  history: WalletCallbackHistory,
  close: WalletCallbackClose,
): void;
