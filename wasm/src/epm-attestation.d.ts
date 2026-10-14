import type { HDWalletModule } from './index.js';

export type EpmSignatureCurve = 'ed25519' | 'secp256k1';

export interface EpmSignatureOptions {
  curve?: EpmSignatureCurve;
}

export interface EpmSignatureResult {
  signature: string;
  timestamp: number;
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

export interface ChainProofResult {
  chain: string;
  valid: boolean;
}

export interface ChainProofVerifyResult {
  valid: boolean;
  results: ChainProofResult[];
}

export function buildCanonicalPayload(params: CanonicalPayloadParams): string;

export function buildEPMSigningContent(epm: Record<string, unknown>): Uint8Array;

export function signEPMContent(
  wallet: HDWalletModule,
  epm: Record<string, unknown>,
  privateKey: Uint8Array,
  options?: EpmSignatureOptions,
): EpmSignatureResult;

export function verifyEPMSignature(
  wallet: HDWalletModule,
  epm: Record<string, unknown>,
  publicKey: Uint8Array,
  options?: EpmSignatureOptions,
): boolean;

export function buildBitcoinChainProof(
  wallet: HDWalletModule,
  params: ChainKeyParams,
): ChainProofData;

export function buildEthereumChainProof(
  wallet: HDWalletModule,
  params: ChainKeyParams,
): ChainProofData;

export function buildSolanaChainProof(
  wallet: HDWalletModule,
  params: ChainKeyParams,
): ChainProofData;

export function buildAllChainProofs(
  wallet: HDWalletModule,
  params: AllChainProofsParams,
): ChainProofData[];

export function verifyChainProof(
  wallet: HDWalletModule,
  proof: ChainProofData,
): boolean;

export function verifyAllChainProofs(
  wallet: HDWalletModule,
  chainProofs: ChainProofData[],
): ChainProofVerifyResult;

/** DER-encode a 64-byte compact r||s ECDSA signature (the SDS EPM annex encoding). */
export function compactSignatureToDer(compact: Uint8Array): Uint8Array;

/** SHA-256(SHA-256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message)). */
export function bitcoinSignedMessageHash(wallet: HDWalletModule, message: Uint8Array): Uint8Array;

/** EIP-191 personal_sign: Keccak-256("\x19Ethereum Signed Message:\n" || decimal(len) || message). */
export function ethereumPersonalSignHash(wallet: HDWalletModule, message: Uint8Array): Uint8Array;
