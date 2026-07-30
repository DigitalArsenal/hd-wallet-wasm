export interface AccountViewBond {
  value?: string;
  label?: string;
}

export interface AccountViewWallet {
  id: string;
  name?: string;
}

export interface AccountViewChip {
  label: string;
  tone?: string;
  title?: string;
}

export interface AccountViewAction {
  label: string;
  onClick: () => unknown;
  title?: string;
  variant?: string;
}

export interface AccountViewTab {
  id: string;
  label?: string;
  render?: (panel: HTMLElement) => void;
}

export interface AccountViewField {
  id: string;
  label?: string;
  value?: string;
  readOnly?: boolean;
  multiline?: boolean;
  placeholder?: string;
  note?: string;
  title?: string;
}

export interface AccountViewStatus {
  text?: string;
  tone?: 'busy' | 'error' | 'ok' | string;
}

export interface AccountViewIdentity {
  fields?: AccountViewField[];
  photoUrl?: string;
  photoStatus?: AccountViewStatus;
  saveStatus?: AccountViewStatus;
  onSave?: (values: Record<string, string>) => unknown;
  onPhoto?: (blob: Blob) => unknown;
  onPhotoRemove?: () => unknown;
}

export interface AccountViewOptions {
  document?: Document;
  title?: string;
  bond?: AccountViewBond;
  wallets?: AccountViewWallet[];
  activeWalletId?: string;
  onWalletChange?: (walletId: string) => void;
  chips?: AccountViewChip[];
  actions?: AccountViewAction[];
  tabs?: AccountViewTab[];
  activeTabId?: string;
  onTabChange?: (tabId: string) => void;
  identity?: AccountViewIdentity;
  onClose?: () => void;
}

export interface AccountViewUpdate {
  title?: string;
  bond?: AccountViewBond;
  chips?: AccountViewChip[];
  actions?: AccountViewAction[];
  wallets?: AccountViewWallet[];
  activeWalletId?: string;
  identity?: AccountViewIdentity;
  activeTabId?: string;
}

export interface AccountView {
  element: HTMLElement;
  panel(id: string): HTMLElement | null;
  getActiveTab(): string | null;
  setActiveTab(id: string): void;
  update(next?: AccountViewUpdate): void;
  destroy(): void;
}

export declare const DEFAULT_ACCOUNT_TABS: ReadonlyArray<{ id: string; label: string }>;

export declare function createAccountView(options?: AccountViewOptions): AccountView;

export declare function mountAccountView(
  container: Element,
  options?: AccountViewOptions,
): AccountView;
