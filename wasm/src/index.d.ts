/**
 * HD Wallet WASM - TypeScript Definitions
 *
 * Comprehensive HD wallet implementation with:
 * - BIP-32/39/44/49/84 support
 * - Multi-curve cryptography (secp256k1, Ed25519, P-256, P-384, X25519)
 * - Multi-chain support (Bitcoin, Ethereum, Solana, Cosmos, Polkadot)
 * - Hardware wallet abstraction (requires bridge)
 * - Transaction building and signing
 */

// Import aligned API types
import { AlignedAPI } from './aligned';

export type BinaryLike = Uint8Array | ArrayBuffer | ArrayBufferView;
export type X509CertificateInput = string | BinaryLike;

export interface SdnPluginTypeRef {
  schemaName: string | null;
  fileIdentifier: string | null;
  schemaHash?: number[];
  acceptsAnyFlatbuffer?: boolean;
}

export interface SdnPluginAcceptedTypeSet {
  setId: string;
  allowedTypes: SdnPluginTypeRef[];
  description?: string | null;
}

export interface SdnPluginPortManifest {
  portId: string;
  displayName?: string | null;
  acceptedTypeSets: SdnPluginAcceptedTypeSet[];
  minStreams?: number;
  maxStreams?: number;
  required?: boolean;
  description?: string | null;
}

export interface SdnPluginMethodManifest {
  methodId: string;
  displayName?: string | null;
  inputPorts: SdnPluginPortManifest[];
  outputPorts: SdnPluginPortManifest[];
  maxBatch?: number;
  drainPolicy?: string | null;
  description?: string | null;
}

export interface SdnPluginCapabilityManifest {
  capabilityId: string;
  required?: boolean;
  description?: string | null;
}

export interface SdnPluginExternalInterfaceManifest {
  interfaceId: string;
  kind?: string | null;
  direction?: string | null;
  capability?: string | null;
  resource?: string | null;
  protocolId?: string | null;
  topic?: string | null;
  path?: string | null;
  required?: boolean;
  acceptedTypes?: SdnPluginTypeRef[];
  description?: string | null;
  properties?: Record<string, unknown>;
}

export interface SdnPluginBuildArtifact {
  artifactId: string;
  kind?: string | null;
  path: string;
  target?: string | null;
  entrySymbol?: string | null;
}

export interface SdnPluginManifest {
  pluginId: string;
  name?: string | null;
  version?: string | null;
  pluginFamily?: string | null;
  description?: string | null;
  methods: SdnPluginMethodManifest[];
  capabilities: SdnPluginCapabilityManifest[];
  externalInterfaces: SdnPluginExternalInterfaceManifest[];
  schemasUsed: SdnPluginTypeRef[];
  buildArtifacts: SdnPluginBuildArtifact[];
  abiVersion?: number;
}

export interface SdnPluginFrame {
  portId: string;
  typeRef?: SdnPluginTypeRef | null;
  alignment?: number;
  offset?: number;
  size?: number;
  ownership?: string;
  generation?: number;
  mutability?: string;
  traceId?: string | null;
  streamId?: number;
  sequence?: number;
  payload: any;
}

export interface SdnPluginInvocationResult {
  outputs: SdnPluginFrame[];
  backlogRemaining: number;
  yielded: boolean;
}

export interface SdnPluginCapabilities {
  randomBytes?: (length: number, context?: Record<string, unknown>) => BinaryLike;
  walletSign?: (request: {
    curve: string;
    payload: any;
    messageBytes: Uint8Array;
    digest: Uint8Array | null;
  }) => {
    signature: BinaryLike;
    publicKey: BinaryLike;
    algorithm?: string;
  };
}

export interface SdnPluginContract {
  manifest: SdnPluginManifest;
  manifestExports: {
    bytesSymbol: string;
    sizeSymbol: string;
  };
  getManifest(): SdnPluginManifest;
  getManifestBytes(): Uint8Array;
  withCapabilities(capabilities: SdnPluginCapabilities): SdnPluginContract;
  invoke(methodId: string, request: { inputs: SdnPluginFrame[] }): SdnPluginInvocationResult;
  encrypt_fields(request: { inputs: SdnPluginFrame[] }): SdnPluginInvocationResult;
  decrypt_fields(request: { inputs: SdnPluginFrame[] }): SdnPluginInvocationResult;
  sign_detached(request: { inputs: SdnPluginFrame[] }): SdnPluginInvocationResult;
  verify_detached(request: { inputs: SdnPluginFrame[] }): SdnPluginInvocationResult;
}

declare const sdnIdentityHandleBrand: unique symbol;

export interface SdnIdentityHandle {
  readonly [sdnIdentityHandleBrand]: true;
}

export interface SdnWasmKeyDescriptor {
  purpose: 'asset-review-approval' | 'contact-encryption' | 'sdn-authentication';
  identityScheme: 'sdn-bip32-slip10-purpose-v1'
    | 'sdn-fast-password-auth-v1-legacy' | 'sdn-bip39-auth-v1-legacy';
  seedProfile: 'password-scrypt-v2' | 'password-fast-v1-legacy'
    | 'bip39-mnemonic-v1-legacy';
  signatureProfile: 'ed25519-over-sha256-jcs-v1'
    | 'ed25519-raw-32-v1' | null;
  curve: 'ed25519' | 'x25519';
  derivation: 'slip10' | 'bip32-scalar-as-ed25519-seed';
  path: string;
  encoding: 'raw';
  publicKeyHex: string;
  bip32Fingerprint: null;
  keyId: `sha256:${string}`;
}

export interface SdnWasmPublicIdentity {
  schemaVersion: 1;
  identityScheme: SdnWasmKeyDescriptor['identityScheme'];
  seedProfile: SdnWasmKeyDescriptor['seedProfile'];
  accountIndex: 0 | 1;
  accountLabel: null;
  accountXpub: string;
  accountPeerId: string;
  accountFingerprint: string;
  keys: readonly SdnWasmKeyDescriptor[];
}

export type SdnRegistryRowId =
  | 'sdn-node-console-v2'
  | 'asset-review-authority-activation-v1'
  | 'asset-review-decision-v1';

export interface RawWalletSignature {
  schemaVersion: 1;
  keyId: `sha256:${string}`;
  identityScheme: 'sdn-fast-password-auth-v1-legacy' | 'sdn-bip39-auth-v1-legacy';
  algorithm: 'ed25519';
  encoding: 'raw';
  signatureProfile: 'ed25519-raw-32-v1';
  signatureHex: string;
}

export interface CanonicalWalletSignature {
  schemaVersion: 1;
  keyId: `sha256:${string}`;
  identityScheme: 'sdn-bip32-slip10-purpose-v1';
  algorithm: 'ed25519';
  encoding: 'raw';
  signatureProfile: 'ed25519-over-sha256-jcs-v1';
  canonicalEnvelope: string;
  signedDigestSha256: string;
  signatureHex: string;
}

export interface SdnLoginV2WireRequest {
  audience: string;
  challengeBase64url: string;
  expiresAt: string;
  issuedAt: string;
  nonce: string;
  protocolVersion: 2;
}

export interface ReviewedTransform {
  translation: readonly [number, number, number];
  rotation: readonly [number, number, number, number];
  scale: readonly [number, number, number];
  upAxis: 'X_UP' | 'Y_UP' | 'Z_UP';
  sourceUnits: 'm' | 'cm' | 'mm' | 'km';
  metersPerSourceUnit: number;
}

interface AssetReviewApprovalRequestBase {
  protocolVersion: 1;
  audience: 'asset-review:assets.ipfs.01';
  requestOrigin: 'https://review.spacedatanetwork.org';
  clientId: 'sdn-asset-review-v1';
  challengeId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  candidateKey: string;
  modelCid: string;
  modelSha256: string;
  modelBytes: number;
  metadataSha256: string;
  previousDecisionHead: string | null;
}

export interface AssetReviewApproveRequest extends AssetReviewApprovalRequestBase {
  decision: 'approve';
  reviewedTransform: ReviewedTransform;
  note: string | null;
}

export interface AssetReviewDisapproveRequest extends AssetReviewApprovalRequestBase {
  decision: 'disapprove';
  reason: string;
}

export type AssetReviewApprovalRequest =
  | AssetReviewApproveRequest
  | AssetReviewDisapproveRequest;

export interface AssetReviewAuthorityActivationRequest {
  protocolVersion: 1;
  audience: 'asset-review-authority:assets.ipfs.01';
  requestOrigin: 'https://review.spacedatanetwork.org';
  clientId: 'sdn-asset-review-v1';
  serviceInstance: 'assets.ipfs.01/asset-review-attestation';
  purpose: 'asset-review-authority-activation';
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  publicKeyHex: string;
  keyId: `sha256:${string}`;
  identityScheme: 'sdn-bip32-slip10-purpose-v1';
  signatureProfile: 'ed25519-over-sha256-jcs-v1';
}

export interface RememberWalletSealInput {
  passwordUtf8: Uint8Array;
  prfOutput: Uint8Array;
  hkdfSalt: Uint8Array;
  nonce: Uint8Array;
  canonicalAad: string;
}

export interface SdnIdentityCapabilities {
  derivePasswordIdentity(input: {
    usernameUtf8: Uint8Array;
    passwordUtf8: Uint8Array;
    accountIndex: 0 | 1;
  }): Promise<{ handle: SdnIdentityHandle; identity: SdnWasmPublicIdentity }>;
  deriveLegacyPasswordIdentity(input: {
    usernameUtf8: Uint8Array;
    passwordUtf8: Uint8Array;
    accountIndex: 0 | 1;
  }): Promise<{ handle: SdnIdentityHandle; identity: SdnWasmPublicIdentity }>;
  importLegacyMnemonicIdentity(input: {
    mnemonicUtf8: Uint8Array;
    accountIndex: 0 | 1;
  }): Promise<{ handle: SdnIdentityHandle; identity: SdnWasmPublicIdentity }>;
  importRememberedIdentity(input: {
    ciphertextAndTag: Uint8Array;
    prfOutput: Uint8Array;
    hkdfSalt: Uint8Array;
    nonce: Uint8Array;
    canonicalUsernameUtf8: Uint8Array;
    canonicalAad: string;
  }): { handle: SdnIdentityHandle; identity: SdnWasmPublicIdentity };
  signSdnLoginV1(handle: SdnIdentityHandle, challenge: Uint8Array): RawWalletSignature;
  signSdnLoginV2(
    handle: SdnIdentityHandle,
    request: SdnLoginV2WireRequest,
    registryRow: 'sdn-node-console-v2',
  ): CanonicalWalletSignature;
  signAssetReviewAuthorityActivation(
    handle: SdnIdentityHandle,
    request: AssetReviewAuthorityActivationRequest,
    registryRow: 'asset-review-authority-activation-v1',
  ): CanonicalWalletSignature;
  signAssetReviewDecision(
    handle: SdnIdentityHandle,
    request: AssetReviewApprovalRequest,
    registryRow: 'asset-review-decision-v1',
  ): CanonicalWalletSignature;
  sealRememberedIdentity(
    handle: SdnIdentityHandle,
    input: RememberWalletSealInput,
  ): Uint8Array;
  destroySdnIdentity(handle: SdnIdentityHandle): void;
}

export interface WalletOriginCapabilities {
  readonly sdn: SdnIdentityCapabilities;
  readonly sha256: (bytes: Uint8Array) => Uint8Array;
}

// =============================================================================
// Module Types
// =============================================================================

export interface HDWalletModule {
  // Module info
  getVersion(): string;
  hasCryptopp(): boolean;
  isFipsMode(): boolean;
  getSupportedCoins(): string[];
  getSupportedCurves(): string[];

  // OpenSSL FIPS support (when built with HD_WALLET_USE_OPENSSL)
  /** Initialize OpenSSL in FIPS mode. Returns true if FIPS mode activated, false if using fallback. */
  initFips(): boolean;
  /** Check if OpenSSL backend is being used for FIPS algorithms */
  isOpenSSL(): boolean;
  /** Check if running in FIPS mode (OpenSSL FIPS provider active) */
  isOpenSSLFips(): boolean;

  // WASI bridge
  wasiHasFeature(feature: WasiFeature): boolean;
  wasiGetWarning(feature: WasiFeature): WasiWarning;
  wasiGetWarningMessage(feature: WasiFeature): string;

  // Entropy
  injectEntropy(entropy: Uint8Array): void;
  getEntropyStatus(): EntropyStatus;

  // BIP-39 Mnemonic
  mnemonic: MnemonicAPI;

  // BIP-32 HD Keys
  hdkey: HDKeyAPI;

  // Multi-curve cryptography
  curves: CurvesAPI;

  // Bitcoin
  bitcoin: BitcoinAPI;

  // Ethereum
  ethereum: EthereumAPI;

  // Cosmos
  cosmos: CosmosAPI;

  // Solana
  solana: SolanaAPI;

  // Polkadot
  polkadot: PolkadotAPI;

  // Hardware wallets (requires bridge)
  hardware: HardwareWalletAPI;

  // Keyring
  keyring: KeyringAPI;

  // Utilities
  utils: UtilsAPI;

  // X.509 certificates
  x509: X509API;

  // Key derivation helpers
  buildSigningPath: typeof buildSigningPath;
  buildEncryptionPath: typeof buildEncryptionPath;
  getSigningKey: typeof getSigningKey;
  getEncryptionKey: typeof getEncryptionKey;

  // libp2p PeerID / IPNS
  libp2p: Libp2pAPI;

  // Canonical SDN plugin-facing contract
  plugin: SdnPluginContract;

  // Purpose-separated, instance-bound SDN wallet capabilities
  readonly sdn: SdnIdentityCapabilities;

  // Authenticated, immutable binding used only by the wallet-origin runtime
  readonly walletOriginCapabilities: WalletOriginCapabilities;

  // Aligned binary API for efficient batch operations
  aligned: AlignedAPI;
}

// =============================================================================
// Enums
// =============================================================================

export enum Curve {
  SECP256K1 = 0,
  ED25519 = 1,
  P256 = 2,
  P384 = 3,
  X25519 = 4
}

export enum CoinType {
  BITCOIN = 0,
  BITCOIN_TESTNET = 1,
  LITECOIN = 2,
  DOGECOIN = 3,
  ETHEREUM = 60,
  ETHEREUM_CLASSIC = 61,
  COSMOS = 118,
  STELLAR = 148,
  BITCOIN_CASH = 145,
  POLKADOT = 354,
  KUSAMA = 434,
  SOLANA = 501,
  BINANCE = 714,
  CARDANO = 1815
}

/**
 * BIP-39 wordlist language selector.
 * ENGLISH is supported in this build; other locale values are reserved and
 * currently return NOT_SUPPORTED.
 */
export enum Language {
  ENGLISH = 0,
  JAPANESE = 1,
  KOREAN = 2,
  SPANISH = 3,
  CHINESE_SIMPLIFIED = 4,
  CHINESE_TRADITIONAL = 5,
  FRENCH = 6,
  ITALIAN = 7,
  CZECH = 8,
  PORTUGUESE = 9
}

export enum WasiFeature {
  RANDOM = 0,
  FILESYSTEM = 1,
  NETWORK = 2,
  USB_HID = 3,
  CLOCK = 4,
  ENVIRONMENT = 5
}

export enum WasiWarning {
  NONE = 0,
  NEEDS_ENTROPY = 1,
  NEEDS_BRIDGE = 2,
  NOT_AVAILABLE_WASI = 3,
  DISABLED_FIPS = 4,
  NEEDS_CAPABILITY = 5
}

export enum EntropyStatus {
  NOT_INITIALIZED = 0,
  INITIALIZED = 1,
  SUFFICIENT = 2
}

export enum BitcoinAddressType {
  P2PKH = 0,
  P2SH = 1,
  P2WPKH = 2,
  P2WSH = 3,
  P2TR = 4
}

export enum Network {
  MAINNET = 0,
  TESTNET = 1
}

export enum X509Encoding {
  PEM = 0,
  DER = 1,
  PKCS12 = 2
}

// =============================================================================
// BIP-39 Mnemonic API
// =============================================================================

export interface MnemonicAPI {
  /**
   * Generate a random mnemonic phrase
   * @param wordCount Number of words (12, 15, 18, 21, or 24)
   * @param language Wordlist language (ENGLISH supported in default build)
   * @throws If entropy not available (WASI) or invalid word count
   */
  generate(wordCount?: number, language?: Language): string;

  /**
   * Validate a mnemonic phrase
   */
  validate(mnemonic: string, language?: Language): boolean;

  /**
   * Convert mnemonic to 64-byte seed
   */
  toSeed(mnemonic: string, passphrase?: string): Uint8Array;

  /**
   * Convert mnemonic to entropy bytes
   */
  toEntropy(mnemonic: string, language?: Language): Uint8Array;

  /**
   * Convert entropy to mnemonic
   */
  fromEntropy(entropy: Uint8Array, language?: Language): string;

  /**
   * Get wordlist for language
   */
  getWordlist(language?: Language): string[];

  /**
   * Get word suggestions for autocomplete
   */
  suggestWords(prefix: string, language?: Language, maxSuggestions?: number): string[];

  /**
   * Check if word is in wordlist
   */
  checkWord(word: string, language?: Language): boolean;
}

// =============================================================================
// BIP-32 HD Key API
// =============================================================================

export interface HDKey {
  /** Derivation path */
  readonly path: string;

  /** Key depth in derivation tree */
  readonly depth: number;

  /** Parent fingerprint */
  readonly parentFingerprint: number;

  /** Child index */
  readonly childIndex: number;

  /** Is this a neutered (public-only) key? */
  readonly isNeutered: boolean;

  /** Elliptic curve */
  readonly curve: Curve;

  /** Get private key (throws if neutered) */
  privateKey(): Uint8Array;

  /** Get public key (compressed) */
  publicKey(): Uint8Array;

  /** Get public key (uncompressed) */
  publicKeyUncompressed(): Uint8Array;

  /** Get chain code */
  chainCode(): Uint8Array;

  /** Get key fingerprint */
  fingerprint(): number;

  /** Derive child key */
  deriveChild(index: number): HDKey;

  /** Derive child key (hardened) */
  deriveHardened(index: number): HDKey;

  /** Derive key at path */
  derivePath(path: string): HDKey;

  /** Get neutered (public-only) version */
  neutered(): HDKey;

  /** Serialize as xprv */
  toXprv(): string;

  /** Serialize as xpub */
  toXpub(): string;

  /** Securely wipe key from memory */
  wipe(): void;

  /** Clone key */
  clone(): HDKey;

  /** Compute libp2p peerID (raw multihash bytes) */
  peerId(): Uint8Array;

  /** Get peerID as base58btc string */
  peerIdString(): string;

  /** Get IPNS hash (CIDv1 base36lower) */
  ipnsHash(): string;
}

export interface HDKeyAPI {
  /**
   * Create master key from seed
   */
  fromSeed(seed: Uint8Array, curve?: Curve): HDKey;

  /**
   * Parse extended private key
   */
  fromXprv(xprv: string): HDKey;

  /**
   * Parse extended public key
   */
  fromXpub(xpub: string): HDKey;

  /**
   * Build BIP-44 path
   */
  buildPath(purpose: number, coinType: number, account?: number, change?: number, index?: number): string;

  /**
   * Parse BIP-44 path
   */
  parsePath(path: string): {
    purpose: number;
    coinType: number;
    account: number;
    change: number;
    index: number;
  };
}

// =============================================================================
// Multi-Curve API
// =============================================================================

export interface CurvesAPI {
  /**
   * Derive public key from private key
   */
  publicKeyFromPrivate(privateKey: Uint8Array, curve: Curve): Uint8Array;

  /**
   * Compress public key
   */
  compressPublicKey(publicKey: Uint8Array, curve: Curve): Uint8Array;

  /**
   * Decompress public key
   */
  decompressPublicKey(publicKey: Uint8Array, curve: Curve): Uint8Array;

  // ECDSA (secp256k1)
  secp256k1: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    signRecoverable(message: Uint8Array, privateKey: Uint8Array): { signature: Uint8Array; recoveryId: number };
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    recover(message: Uint8Array, signature: Uint8Array, recoveryId: number): Uint8Array;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // EdDSA (Ed25519)
  ed25519: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  };

  // ECDSA (P-256)
  p256: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // ECDSA (P-384)
  p384: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // X25519 (key exchange only)
  x25519: {
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };
}

// =============================================================================
// Bitcoin API
// =============================================================================

export interface BitcoinAPI {
  /**
   * Get address from public key
   */
  getAddress(publicKey: Uint8Array, type: BitcoinAddressType, network?: Network): string;

  /**
   * Validate Bitcoin address
   */
  validateAddress(address: string): boolean;

  /**
   * Decode Bitcoin address
   */
  decodeAddress(address: string): { type: BitcoinAddressType; hash: Uint8Array; network: Network };

  /**
   * Sign message (Bitcoin Signed Message format)
   */
  signMessage(message: string, privateKey: Uint8Array): string;

  /**
   * Verify signed message
   */
  verifyMessage(message: string, signature: string, address: string): boolean;

  /**
   * Transaction builder
   */
  tx: BitcoinTxBuilder;
}

export interface BitcoinTxBuilder {
  create(): BitcoinTx;
}

export interface BitcoinTx {
  addInput(txid: string, vout: number, sequence?: number): this;
  addOutput(address: string, amount: bigint): this;
  sign(inputIndex: number, privateKey: Uint8Array, redeemScript?: Uint8Array): this;
  serialize(): Uint8Array;
  getTxid(): string;
  getSize(): number;
  getVsize(): number;
}

// =============================================================================
// Ethereum API
// =============================================================================

export interface EthereumAPI {
  /**
   * Get address from public key
   */
  getAddress(publicKey: Uint8Array): string;

  /**
   * Get checksummed address (EIP-55)
   */
  getChecksumAddress(address: string): string;

  /**
   * Validate Ethereum address
   */
  validateAddress(address: string): boolean;

  /**
   * Sign message (EIP-191)
   */
  signMessage(message: string, privateKey: Uint8Array): string;

  /**
   * Sign typed data (EIP-712)
   */
  signTypedData(typedData: object, privateKey: Uint8Array): string;

  /**
   * Verify message signature
   */
  verifyMessage(message: string, signature: string): string;

  /**
   * Transaction builder
   */
  tx: EthereumTxBuilder;
}

export interface EthereumTxBuilder {
  create(params: {
    nonce: number;
    gasPrice?: bigint;
    gasLimit: bigint;
    to?: string;
    value?: bigint;
    data?: Uint8Array;
    chainId: number;
  }): EthereumTx;

  createEIP1559(params: {
    nonce: number;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
    gasLimit: bigint;
    to?: string;
    value?: bigint;
    data?: Uint8Array;
    chainId: number;
  }): EthereumTx;
}

export interface EthereumTx {
  sign(privateKey: Uint8Array): this;
  serialize(): Uint8Array;
  getHash(): string;
}

// =============================================================================
// Cosmos API
// =============================================================================

export interface CosmosAPI {
  getAddress(publicKey: Uint8Array, prefix?: string): string;
  validateAddress(address: string): boolean;
  signAmino(doc: object, privateKey: Uint8Array): object;
  signDirect(bodyBytes: Uint8Array, authInfoBytes: Uint8Array, chainId: string, accountNumber: bigint, privateKey: Uint8Array): object;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Solana API
// =============================================================================

export interface SolanaAPI {
  getAddress(publicKey: Uint8Array): string;
  validateAddress(address: string): boolean;
  signMessage(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verifyMessage(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Polkadot API
// =============================================================================

export interface PolkadotAPI {
  getAddress(publicKey: Uint8Array, ss58Prefix?: number): string;
  validateAddress(address: string): boolean;
  signMessage(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verifyMessage(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Hardware Wallet API (requires bridge)
// =============================================================================

export interface HardwareWalletAPI {
  /**
   * Check if hardware wallet features are available
   * Returns false in WASI without bridge
   */
  isAvailable(): boolean;

  /**
   * Enumerate connected hardware wallets
   */
  enumerate(): Promise<HardwareWalletDevice[]>;

  /**
   * Connect to a hardware wallet
   */
  connect(devicePath: string): Promise<HardwareWallet>;
}

export interface HardwareWalletDevice {
  vendorId: number;
  productId: number;
  serialNumber: string;
  manufacturer: string;
  product: string;
  path: string;
}

export interface HardwareWallet {
  readonly vendor: string;
  readonly model: string;
  readonly firmwareVersion: string;
  readonly isConnected: boolean;

  getPublicKey(path: string, curve?: Curve): Promise<Uint8Array>;
  signTransaction(path: string, transaction: Uint8Array): Promise<Uint8Array>;
  signMessage(path: string, message: string): Promise<Uint8Array>;
  ping(): Promise<boolean>;
  disconnect(): void;
}

// =============================================================================
// Keyring API
// =============================================================================

export interface KeyringAPI {
  create(): Keyring;
}

export interface Keyring {
  addWallet(seed: Uint8Array, name?: string): string;
  removeWallet(id: string): void;
  getWalletCount(): number;
  getAccounts(walletId: string, coinType: CoinType, count?: number): string[];
  signTransaction(walletId: string, path: string, transaction: Uint8Array): Uint8Array;
  signMessage(walletId: string, path: string, message: Uint8Array): Uint8Array;
  destroy(): void;
}

// =============================================================================
// Utilities API
// =============================================================================

export interface UtilsAPI {
  // Hashing (sync - Crypto++)
  sha256(data: Uint8Array): Uint8Array;
  sha512(data: Uint8Array): Uint8Array;
  keccak256(data: Uint8Array): Uint8Array;
  ripemd160(data: Uint8Array): Uint8Array;
  hash160(data: Uint8Array): Uint8Array;
  blake2b(data: Uint8Array, outputLength?: number): Uint8Array;
  blake2s(data: Uint8Array, outputLength?: number): Uint8Array;

  // Key derivation
  hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array;
  scrypt(password: Uint8Array, salt: Uint8Array, n: number, r: number, p: number, length: number): Uint8Array;

  // AES-GCM encryption/decryption (WASM/OpenSSL)
  aesGcm: {
    encrypt(key: Uint8Array, plaintext: Uint8Array, iv: Uint8Array, aad?: Uint8Array): { ciphertext: Uint8Array; tag: Uint8Array };
    decrypt(key: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Uint8Array;
  };

  // Random number generation
  getRandomBytes(length: number): Uint8Array;
  generateIv(): Uint8Array;
  generateAesKey(bits?: number): Uint8Array;

  // Encoding
  encodeBase58(data: Uint8Array): string;
  decodeBase58(str: string): Uint8Array;
  encodeBase58Check(data: Uint8Array): string;
  decodeBase58Check(str: string): Uint8Array;
  encodeBech32(hrp: string, data: Uint8Array): string;
  decodeBech32(str: string): { hrp: string; data: Uint8Array };
  encodeHex(data: Uint8Array): string;
  decodeHex(str: string): Uint8Array;
  encodeBase64(data: Uint8Array): string;
  decodeBase64(str: string): Uint8Array;

  // Memory
  secureWipe(data: Uint8Array): void;
}

// =============================================================================
// X.509 API
// =============================================================================

export interface X509WalletAttestationOptions {
  curve: Curve;
  privateKey: BinaryLike;
  keyLabel?: string;
  commentPrefix?: string;
}

export interface X509CertificateOptions {
  subjectDn: string;
  serialHex?: string;
  notBeforeUnix: number;
  notAfterUnix: number;
  isCa?: boolean;
  pathLen?: number;
  dnsNames?: string[];
  ipAddresses?: string[];
  emailAddresses?: string[];
  uriNames?: string[];
  keyUsage?: string[];
  extendedKeyUsage?: string[];
  friendlyName?: string;
  walletAttestation?: X509WalletAttestationOptions;
}

export interface X509ParsedCertificate {
  subjectDn: string;
  issuerDn: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  isCa: boolean;
  dnsNames: string[];
  ipAddresses: string[];
  emailAddresses: string[];
  uriNames: string[];
  walletAttestationComment: string;
  walletAttestationValid: boolean;
}

export interface X509Pkcs12Bundle {
  certificatePem: string;
  privateKeyPem: string;
  chainPem: string;
}

export interface X509API {
  isAvailable(): boolean;
  generatePrivateKey(curve: Curve): Uint8Array;
  exportPrivateKeyPem(curve: Curve, privateKey: BinaryLike): string;
  importPrivateKeyPem(curve: Curve, pem: string): Uint8Array;
  createSelfSignedCertificate(
    options: X509CertificateOptions,
    certificateCurve: Curve,
    certificatePrivateKey: BinaryLike,
    outputEncoding?: X509Encoding
  ): string | Uint8Array;
  issueCertificate(
    options: X509CertificateOptions,
    issuerCurve: Curve,
    issuerPrivateKey: BinaryLike,
    issuerCertificate: X509CertificateInput,
    issuerCertificateEncoding: X509Encoding,
    subjectCurve: Curve,
    subjectPrivateKey: BinaryLike,
    outputEncoding?: X509Encoding
  ): string | Uint8Array;
  convertCertificate(
    certificate: X509CertificateInput,
    inputEncoding: X509Encoding,
    outputEncoding: X509Encoding
  ): string | Uint8Array;
  parseCertificate(certificate: X509CertificateInput, inputEncoding?: X509Encoding): X509ParsedCertificate;
  verifyWalletAttestation(certificate: X509CertificateInput, inputEncoding?: X509Encoding): boolean;
  exportPkcs12(
    certificate: X509CertificateInput,
    certificateEncoding: X509Encoding,
    privateKeyCurve: Curve,
    privateKey: BinaryLike,
    password: string,
    friendlyName?: string,
    chainPem?: X509CertificateInput
  ): Uint8Array;
  importPkcs12(pkcs12Bundle: BinaryLike, password: string): X509Pkcs12Bundle;
}

// =============================================================================
// libp2p PeerID / IPNS API
// =============================================================================

export interface Libp2pAPI {
  /** Compute libp2p peerID from a public key */
  peerIdFromPublicKey(publicKey: Uint8Array, curve: Curve): Uint8Array;

  /** Encode peerID bytes as base58btc string */
  peerIdToString(peerIdBytes: Uint8Array): string;

  /** Compute IPNS hash (CIDv1 base36lower, 'k' prefix) */
  ipnsHash(peerIdBytes: Uint8Array): string;

  /** Compute IPNS hash (CIDv1 base32lower, 'b' prefix) */
  ipnsHashBase32(peerIdBytes: Uint8Array): string;

  /** Derive PeerID string directly from a Base58Check-encoded xpub */
  peerIdFromXpub(xpub: string): string;

  /** Derive IPNS hash (CIDv1 base36lower) directly from an xpub */
  ipnsHashFromXpub(xpub: string): string;
}

// =============================================================================
// Key Derivation Path Helpers
// =============================================================================

/** Keypair result from getSigningKey / getEncryptionKey */
export interface DerivedKeypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  path: string;
}

/** Build a BIP-44 signing key path: m/44'/coinType'/account'/0/index */
export function buildSigningPath(coinType: string | number, account?: string | number, index?: string | number): string;

/** Build a BIP-44 encryption key path: m/44'/coinType'/account'/1/index */
export function buildEncryptionPath(coinType: string | number, account?: string | number, index?: string | number): string;

/** Derive signing keypair at m/44'/coinType'/account'/0/index */
export function getSigningKey(hdRoot: HDKey, coinType: string | number, account?: string | number, index?: string | number): DerivedKeypair;

/** Derive encryption keypair at m/44'/coinType'/account'/1/index */
export function getEncryptionKey(hdRoot: HDKey, coinType: string | number, account?: string | number, index?: string | number): DerivedKeypair;

/** Well-known coin types */
export enum WellKnownCoinType {
  SDN = 0,
  BITCOIN = 0,
  ETHEREUM = 60,
  SOLANA = 501,
}

// =============================================================================
// Module Initialization
// =============================================================================

/**
 * Initialize the HD Wallet WASM module
 * @param wasmPath - Optional path to WASM file
 */
export default function init(wasmPath?: string): Promise<HDWalletModule>;

/**
 * Create HD Wallet instance (alternative syntax)
 * @param wasmPath - Optional path to WASM file
 */
export function createHDWallet(wasmPath?: string): Promise<HDWalletModule>;

/** Resolve the immutable wallet-origin binding for its exact initialized owner. */
export function getWalletOriginCapabilities(
  module: HDWalletModule,
): WalletOriginCapabilities;

export const HD_WALLET_SDN_PLUGIN_MANIFEST: SdnPluginManifest;
export const SDN_PLUGIN_MANIFEST_EXPORTS: {
  bytesSymbol: string;
  sizeSymbol: string;
};

// =============================================================================
// EPM Attestation
// =============================================================================

export interface ChainProofData {
  CHAIN: string;
  ADDRESS: string;
  PUBLIC_KEY: string;
  KEY_PATH: string;
  SIGNATURE: string;
  SIGNED_PAYLOAD: string;
  ALGORITHM: string;
  ENCODING: string;
}

export interface CanonicalPayloadParams {
  xpub: string;
  signingPubKeyHex: string;
  encryptionPubKeyHex: string;
  issuedAt: number;
  identityPubKeyHex?: string;
  version?: string;
}

export interface ChainKeyParams {
  address: string;
  publicKeyHex: string;
  privateKey: Uint8Array;
  keyPath: string;
  canonicalPayload: string;
}

export interface AllChainProofsParams {
  canonicalPayload: string;
  bitcoin?: Omit<ChainKeyParams, 'canonicalPayload'>;
  ethereum?: Omit<ChainKeyParams, 'canonicalPayload'>;
  solana?: Omit<ChainKeyParams, 'canonicalPayload'>;
}

export interface ChainProofVerifyResult {
  valid: boolean;
  results: Array<{ chain: string; valid: boolean }>;
}

/** Build a canonical attestation payload for chain proof signing */
export function buildCanonicalPayload(params: CanonicalPayloadParams): string;

/** Build canonical EPM content bytes for signing (excludes SIGNATURE and SIGNATURE_TIMESTAMP) */
export function buildEPMSigningContent(epm: Record<string, unknown>): Uint8Array;

/** Sign EPM content with an Ed25519 private key */
export function signEPMContent(wallet: HDWalletModule, epm: Record<string, unknown>, ed25519PrivateKey: Uint8Array): { signature: string; timestamp: number };

/** Verify an EPM content signature */
export function verifyEPMSignature(wallet: HDWalletModule, epm: Record<string, unknown>, ed25519PublicKey: Uint8Array): boolean;

/** Build a Bitcoin chain proof */
export function buildBitcoinChainProof(wallet: HDWalletModule, params: ChainKeyParams): ChainProofData;

/** Build an Ethereum chain proof */
export function buildEthereumChainProof(wallet: HDWalletModule, params: ChainKeyParams): ChainProofData;

/** Build a Solana chain proof */
export function buildSolanaChainProof(wallet: HDWalletModule, params: ChainKeyParams): ChainProofData;

/** Build all chain proofs for a full identity attestation */
export function buildAllChainProofs(wallet: HDWalletModule, params: AllChainProofsParams): ChainProofData[];

/** Verify a single chain proof */
export function verifyChainProof(wallet: HDWalletModule, proof: ChainProofData): boolean;

/** Verify all chain proofs in an EPM */
export function verifyAllChainProofs(wallet: HDWalletModule, chainProofs: ChainProofData[]): ChainProofVerifyResult;
