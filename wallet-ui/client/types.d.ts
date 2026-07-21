export type WalletRelayOperation =
  | 'sdn.wallet.connect.v1'
  | 'sdn.wallet.account.v1'
  | 'sdn.auth.raw-challenge.v1'
  | 'sdn.auth.jcs-envelope.v2'
  | 'sdn.asset-review.authority-activation.v1'
  | 'sdn.asset-review.decision.v1';

export type WalletClientStatus = 'dormant' | 'opening' | 'connected' | 'error';
export type SdnIdentityScheme = 'sdn-bip32-slip10-purpose-v1';
export type SdnSeedProfile = 'password-scrypt-v2';
export type Sha256KeyId = `sha256:${string}`;

export interface WalletKeyDescriptor {
  readonly purpose:
    | 'asset-review-approval'
    | 'contact-encryption'
    | 'sdn-authentication';
  readonly identityScheme: SdnIdentityScheme;
  readonly seedProfile: SdnSeedProfile;
  readonly signatureProfile: 'ed25519-over-sha256-jcs-v1' | null;
  readonly curve: 'ed25519' | 'x25519';
  readonly derivation: 'slip10';
  readonly path: string;
  readonly encoding: 'raw';
  readonly publicKeyHex: string;
  readonly bip32Fingerprint: null;
  readonly keyId: Sha256KeyId;
}

export interface WalletPublicIdentity {
  readonly schemaVersion: 1;
  readonly identityScheme: SdnIdentityScheme;
  readonly seedProfile: SdnSeedProfile;
  readonly accountIndex: 0;
  readonly accountLabel: null;
  readonly accountXpub: string;
  readonly accountPeerId: string;
  readonly accountFingerprint: string;
  readonly keys: readonly WalletKeyDescriptor[];
}

export interface WalletClientError {
  readonly code: string;
  readonly message: string;
}

export interface WalletClientSnapshot {
  readonly status: WalletClientStatus;
  readonly identity: WalletPublicIdentity | null;
  readonly connectionExpiresAt?: string;
  readonly error?: WalletClientError;
}

export interface SdnLoginV1Request {
  readonly protocolVersion: 1;
  readonly challenge: Uint8Array;
}

export interface SdnLoginV1WireRequest {
  readonly challengeBase64url: string;
  readonly protocolVersion: 1;
}

export interface SdnLoginV2Request {
  readonly protocolVersion: 2;
  readonly audience: 'sdn-login:sdn.spaceaware.io';
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly challenge: Uint8Array;
}

export interface SdnLoginV2WireRequest {
  readonly audience: 'sdn-login:sdn.spaceaware.io';
  readonly challengeBase64url: string;
  readonly expiresAt: string;
  readonly issuedAt: string;
  readonly nonce: string;
  readonly protocolVersion: 2;
}

export interface ReviewedTransform {
  readonly translation: readonly [number, number, number];
  readonly rotation: readonly [number, number, number, number];
  readonly scale: readonly [number, number, number];
  readonly upAxis: 'X_UP' | 'Y_UP' | 'Z_UP';
  readonly sourceUnits: 'm' | 'cm' | 'mm' | 'km';
  readonly metersPerSourceUnit: number;
}

export interface AssetReviewApprovalRequestBase {
  readonly protocolVersion: 1;
  readonly audience: 'asset-review:assets.ipfs.01';
  readonly requestOrigin: 'https://review.spacedatanetwork.org';
  readonly clientId: 'sdn-asset-review-v1';
  readonly challengeId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly candidateKey: string;
  readonly modelCid: string;
  readonly modelSha256: string;
  readonly modelBytes: number;
  readonly metadataSha256: string;
  readonly previousDecisionHead: string | null;
}

export interface AssetReviewApproveRequest extends AssetReviewApprovalRequestBase {
  readonly decision: 'approve';
  readonly reviewedTransform: ReviewedTransform;
  readonly note: string | null;
}

export interface AssetReviewDisapproveRequest extends AssetReviewApprovalRequestBase {
  readonly decision: 'disapprove';
  readonly reason: string;
}

export type AssetReviewApprovalRequest =
  | AssetReviewApproveRequest
  | AssetReviewDisapproveRequest;

export interface AssetReviewAuthorityActivationRequest {
  readonly protocolVersion: 1;
  readonly audience: 'asset-review-authority:assets.ipfs.01';
  readonly requestOrigin: 'https://review.spacedatanetwork.org';
  readonly clientId: 'sdn-asset-review-v1';
  readonly serviceInstance: 'assets.ipfs.01/asset-review-attestation';
  readonly purpose: 'asset-review-authority-activation';
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly publicKeyHex: string;
  readonly keyId: Sha256KeyId;
  readonly identityScheme: SdnIdentityScheme;
  readonly signatureProfile: 'ed25519-over-sha256-jcs-v1';
}

export interface WalletSignatureBase {
  readonly schemaVersion: 1;
  readonly keyId: Sha256KeyId;
  readonly identityScheme:
    | SdnIdentityScheme
    | 'sdn-fast-password-auth-v1-legacy'
    | 'sdn-bip39-auth-v1-legacy';
  readonly algorithm: 'ed25519';
  readonly encoding: 'raw';
  readonly signatureHex: string;
}

export interface RawWalletSignature extends WalletSignatureBase {
  readonly identityScheme:
    | 'sdn-fast-password-auth-v1-legacy'
    | 'sdn-bip39-auth-v1-legacy';
  readonly signatureProfile: 'ed25519-raw-32-v1';
}

export interface CanonicalWalletSignature extends WalletSignatureBase {
  readonly identityScheme: SdnIdentityScheme;
  readonly signatureProfile: 'ed25519-over-sha256-jcs-v1';
  readonly canonicalEnvelope: string;
  readonly signedDigestSha256: string;
}

export interface WalletConnectionWireResult {
  readonly connectionExpiresAt: string | null;
  readonly event: 'connected' | 'disconnected';
  readonly identity: WalletPublicIdentity | null;
  readonly schemaVersion: 1;
}

export interface WalletPublicClient {
  getSnapshot(): WalletClientSnapshot;
  subscribe(listener: (value: WalletClientSnapshot) => void): () => void;
  connect(): Promise<WalletPublicIdentity>;
  openAccount(): Promise<void>;
  disconnect(): Promise<void>;
  destroy(): Promise<void>;
}

export interface SdnWalletClient extends WalletPublicClient {
  requestSdnLoginV1(value: SdnLoginV1Request): Promise<RawWalletSignature>;
  requestSdnLoginV2(value: SdnLoginV2Request): Promise<CanonicalWalletSignature>;
}

export interface AssetReviewWalletClient extends WalletPublicClient {
  requestAuthorityActivation(value: AssetReviewAuthorityActivationRequest):
    Promise<CanonicalWalletSignature>;
  requestAssetReviewApproval(value: AssetReviewApprovalRequest):
    Promise<CanonicalWalletSignature>;
}

export interface RegistryOperationBinding {
  readonly operation: WalletRelayOperation;
  readonly audience:
    | 'sdn-login:sdn.spaceaware.io'
    | 'asset-review-authority:assets.ipfs.01'
    | 'asset-review:assets.ipfs.01'
    | null;
  readonly maxLifetimeSeconds: 300;
  readonly registryRow:
    | 'sdn-node-console-v2'
    | 'asset-review-authority-activation-v1'
    | 'asset-review-decision-v1'
    | null;
  readonly serviceInstance: 'assets.ipfs.01/asset-review-attestation' | null;
  readonly serviceActivationState: 'activated' | 'unactivated' | null;
}

export interface WalletClientRegistryRow {
  readonly clientDisplayName: string;
  readonly clientId: string;
  readonly requestOrigin: `https://${string}`;
  readonly callbackUri: `https://${string}`;
  readonly allowedOperations: readonly WalletRelayOperation[];
  readonly audiences: readonly Exclude<RegistryOperationBinding['audience'], null>[];
  readonly operationBindings: readonly RegistryOperationBinding[];
}

export interface WalletClientRegistryV1 {
  readonly schemaVersion: 1;
  readonly registryReleaseSha256: string;
  readonly clients: readonly WalletClientRegistryRow[];
}

export interface ResolvedRegistryBinding extends RegistryOperationBinding {
  readonly clientDisplayName: string;
  readonly clientId: string;
  readonly requestOrigin: `https://${string}`;
  readonly callbackUri: `https://${string}`;
  readonly registryReleaseSha256: string;
}
