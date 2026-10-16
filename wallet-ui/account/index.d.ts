export interface AccountViewAvatar {
  /** A photo URL the caller serves. */
  url?: string;
  /** Initials shown when there is no photo (derived from the title when absent). */
  initials?: string;
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
  /** The SDN peer ID: shown short (12D3KooW…x7Qp) and copied in full. */
  peerId?: string;
  avatar?: AccountViewAvatar;
  /** The quiet status word at the right of the identity bar. */
  status?: string;
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
  peerId?: string;
  avatar?: AccountViewAvatar | null;
  status?: string;
  chips?: AccountViewChip[];
  actions?: AccountViewAction[];
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

/** Profile · Messages · People · Assets · Settings */
export declare const DEFAULT_ACCOUNT_TABS: ReadonlyArray<{ id: string; label: string }>;

export declare function createAccountView(options?: AccountViewOptions): AccountView;

export declare function mountAccountView(
  container: Element,
  options?: AccountViewOptions,
): AccountView;
