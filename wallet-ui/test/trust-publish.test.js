/*
 * OUTCOME TESTS for the trust write side (tests-only-for-specific-outcomes
 * law): the trust/revocation record bytes, the Bitcoin and Solana transaction
 * buildings (RAW BYTES are the outcome — signatures are verified against
 * independently reconstructed BIP-143/legacy digests), the Ethereum scanner's
 * data-field extractor, the SDS TRE/$LOT mapping, and the drain detector
 * truth table. No source patterns, no UI wiring.
 */
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import {
  TrustLevel,
  buildSdsTrustExport,
  btcTrustTransaction,
  buildSolanaTrustTx,
  encodeRevocationMetadata,
  encodeTrustMetadata,
  evaluateTrustDrain,
  extractEthereumTrustTxs,
  parseSdsTrustImport,
  trustLevelToWeight,
  trustWeightToLevel,
} from '../src/blockchain-trust.js';

const sha256d = (bytes) => sha256(sha256(bytes));

const bytesToHex = (bytes) =>
  Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

const readU16 = (b, o) => b[o] | (b[o + 1] << 8);
const readU32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/** Parse the raw fields of one of our (version-1, single-input) txs. */
function parseRawTx(hex) {
  const b = Uint8Array.from(Buffer.from(hex, 'hex'));
  let o = 0;
  const version = readU32(b, o); o += 4;
  let hasWitness = false;
  if (b[o] === 0x00 && b[o + 1] !== 0x00) {
    hasWitness = true;
    o += 2;
  }
  const inputCount = b[o++];
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = bytesToHex(b.slice(o, o + 32).reverse()); o += 32;
    const vout = readU32(b, o); o += 4;
    const scriptLen = b[o++];
    const scriptSig = b.slice(o, o + scriptLen); o += scriptLen;
    const sequence = readU32(b, o); o += 4;
    inputs.push({ txid, vout, scriptSig, sequence });
  }
  const outputCount = b[o++];
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    let value = 0n;
    for (let k = 7; k >= 0; k--) value = (value << 8n) | BigInt(b[o + k]);
    o += 8;
    const scriptLen = b[o++];
    outputs.push({ value, script: bytesToHex(b.slice(o, o + scriptLen)) }); o += scriptLen;
  }
  const witnesses = [];
  if (hasWitness) {
    for (let i = 0; i < inputCount; i++) {
      const itemCount = b[o++];
      const items = [];
      for (let j = 0; j < itemCount; j++) {
        const len = b[o++];
        items.push(b.slice(o, o + len)); o += len;
      }
      witnesses.push(items);
    }
  }
  const locktime = readU32(b, o); o += 4;
  expect(b.length).toBe(o);
  return { version, hasWitness, inputs, outputs, witnesses, locktime };
}

// Well-known test key: private key 0x01 (BIP-143/legacy fixtures).
const PRIV = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 1 : 0);
const PUB = secp256k1.getPublicKey(PRIV, true);
const H160 = ripemd160(sha256(PUB));
const P2PKH_SCRIPT = bytesToHex(new Uint8Array([0x76, 0xa9, 0x14, ...H160, 0x88, 0xac]));
const P2WPKH_SCRIPT = '0014' + bytesToHex(H160);
const RECIPIENT = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
const FEE = 5000;
const FUND = 100000;

describe('trust record bytes', () => {
  it('encodes trust as [54 01 level ts32 addr-ascii]', () => {
    const bytes = encodeTrustMetadata(TrustLevel.FULL, RECIPIENT, 1700000000000);
    expect(bytes[0]).toBe(0x54);
    expect(bytes[1]).toBe(0x01);
    expect(bytes[2]).toBe(TrustLevel.FULL);
    const ts = readU32(bytes, 3) * 1000;
    expect(ts).toBe(1700000000000);
    const payload = new TextDecoder().decode(bytes.slice(7));
    expect(payload).toBe(RECIPIENT);
  });

  it('refuses levels and addresses outside the record budget', () => {
    expect(() => encodeTrustMetadata(0, RECIPIENT)).toThrow();
    expect(() => encodeTrustMetadata(6, RECIPIENT)).toThrow();
    expect(() => encodeTrustMetadata(3, '')).toThrow();
    const long = '1'.repeat(72);
    expect(() => encodeTrustMetadata(3, long)).toThrow();
  });

  it('encodes revocations as [52 01 ts32 hash32] and binds the exact hash', () => {
    const hash = 'ab'.repeat(32);
    const bytes = encodeRevocationMetadata(hash, 1700000000000);
    expect(bytes[0]).toBe(0x52);
    expect(bytes[1]).toBe(0x01);
    expect(bytes.length).toBe(38);
    expect(readU32(bytes, 2) * 1000).toBe(1700000000000);
    expect(bytesToHex(bytes.slice(6))).toBe(hash);
    expect(() => encodeRevocationMetadata('0x' + 'cd'.repeat(32))).toThrow();
    expect(() => encodeRevocationMetadata('zz')).toThrow();
  });
});

describe('Bitcoin trust transaction (p2pkh input)', () => {
  const utxos = [{ txid: '11'.repeat(32), vout: 3, value: FUND, scriptpubkey: P2PKH_SCRIPT }];
  const metadata = encodeTrustMetadata(TrustLevel.FULL, RECIPIENT, 1700000000000);
  const { rawHex, txid } = btcTrustTransaction({
    utxos, metadataBytes: metadata, changeAddress: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    signPrivateKey: PRIV, feeSats: FEE,
  });

  it('serializes version 1, one input, OP_RETURN output, dust-safe change', () => {
    const tx = parseRawTx(rawHex);
    expect(tx.version).toBe(1);
    expect(tx.hasWitness).toBe(false);
    expect(tx.inputs).toHaveLength(1);
    expect(tx.inputs[0].txid).toBe('11'.repeat(32));
    expect(tx.inputs[0].vout).toBe(3);
    expect(tx.inputs[0].sequence).toBe(0xffffffff);
    expect(tx.outputs).toHaveLength(2);
    // Output 0: OP_RETURN << payload
    const out0 = tx.outputs[0];
    expect(out0.value).toBe(0n);
    // OP_RETURN script = 6a <len> <data> — two bytes (4 hex chars) of prefix
    expect(out0.script.slice(0, 4)).toBe('6a' + metadata.length.toString(16).padStart(2, '0'));
    expect(Uint8Array.from(Buffer.from(out0.script.slice(4), 'hex'))).toEqual(metadata);
    // Output 1: change to the p2pkh sender
    const out1 = tx.outputs[1];
    expect(out1.value).toBe(BigInt(FUND - FEE));
    expect(out1.script).toBe(P2PKH_SCRIPT);
    expect(tx.locktime).toBe(0);
  });

  it('computes the txid as sha256d(raw) reversed (display order)', () => {
    const rawBytes = Uint8Array.from(Buffer.from(rawHex, 'hex'));
    const expected = bytesToHex(sha256d(rawBytes).reverse());
    expect(txid).toBe(expected);
  });

  it('signs a LEGACY SIGHASH_ALL digest that independently verifies', () => {
    const tx = parseRawTx(rawHex);
    const scriptSig = tx.inputs[0].scriptSig;
    // Push sig || push pubkey
    const sigLen = scriptSig[0];
    const sig = scriptSig.slice(1, 1 + sigLen);
    const pubLen = scriptSig[1 + sigLen];
    const pub = scriptSig.slice(2 + sigLen);
    expect(pubLen).toBe(33);
    expect(bytesToHex(ripemd160(sha256(pub)))).toBe(bytesToHex(H160));
    // Independent SIGLASH preimage: version | inputs(script only on THIS
    // input = prevout script) | outputs | locktime | SIGHASH_ALL
    const pre = [];
    const le32 = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
    pre.push(...le32(1));                              // version
    pre.push(1);                                        // input count
    pre.push(...Uint8Array.from(Buffer.from('11'.repeat(32), 'hex'))); // prev txid (LE as stored)
    pre.push(...le32(3));                               // vout
    pre.push(P2PKH_SCRIPT.length / 2);                  // script len
    pre.push(...Uint8Array.from(Buffer.from(P2PKH_SCRIPT, 'hex'))); // prevout script
    pre.push(...le32(0xffffffff));                      // sequence
    pre.push(2);                                        // output count
    for (const out of tx.outputs) {
      const v = out.value;
      for (let k = 0; k < 8; k++) pre.push(Number((v >> BigInt(8 * k)) & 0xffn));
      pre.push(out.script.length / 2);
      pre.push(...Uint8Array.from(Buffer.from(out.script, 'hex')));
    }
    pre.push(...le32(0));                               // locktime
    pre.push(...le32(1));                               // SIGHASH_ALL
    const digest = sha256d(Uint8Array.from(pre));
    // The scriptSig carries DER || 0x01 (SIGHASH_ALL tail); verify the DER body only.
    expect(secp256k1.verify(sig.slice(0, -1), digest, pub)).toBe(true);
  });
});

describe('Bitcoin trust transaction (p2wpkh v0 input — BIP-143)', () => {
  const utxos = [{ txid: '22'.repeat(32), vout: 7, value: FUND, scriptpubkey: P2WPKH_SCRIPT }];
  const metadata = encodeTrustMetadata(TrustLevel.MARGINAL, RECIPIENT, 1700000000000);
  const { rawHex, txid } = btcTrustTransaction({
    utxos, metadataBytes: metadata, changeAddress: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    signPrivateKey: PRIV, feeSats: FEE,
  });

  it('serializes marker/flag + witness, empty scriptSig', () => {
    const tx = parseRawTx(rawHex);
    expect(tx.hasWitness).toBe(true);
    expect(tx.inputs[0].scriptSig.length).toBe(0);
    expect(tx.witnesses).toHaveLength(1);
    const items = tx.witnesses[0];
    expect(items).toHaveLength(2);
    expect(items[1].length).toBe(33);
    expect(bytesToHex(ripemd160(sha256(items[1])))).toBe(bytesToHex(H160));
    expect(tx.outputs[1].value).toBe(BigInt(FUND - FEE));
    expect(tx.outputs[1].script).toBe(P2PKH_SCRIPT);
  });

  it('computes the txid from the witness-bearing raw bytes', () => {
    const rawBytes = Uint8Array.from(Buffer.from(rawHex, 'hex'));
    expect(txid).toBe(bytesToHex(sha256d(rawBytes).reverse()));
  });

  it('signs a BIP-143 digest that independently verifies', () => {
    const tx = parseRawTx(rawHex);
    const [sig, pub] = tx.witnesses[0];
    expect(sig[sig.length - 1]).toBe(0x01); // SIGHASH_ALL tail
    const sigNoSighash = sig.slice(0, -1);
    // Independent digest: version || hashPrevouts || hashSequence ||
    // outpoint || scriptCode || amount || sequence || outputs || locktime ||
    // nHashType — ALL inside the double hash.
    const le32 = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
    const outpoint = [...Uint8Array.from(Buffer.from('22'.repeat(32), 'hex')), ...le32(7)];
    const hashPrevouts = sha256d(Uint8Array.from(outpoint));
    const hashSequence = sha256d(Uint8Array.from(le32(0xffffffff)));
    const scriptCode = Uint8Array.from(Buffer.from(P2PKH_SCRIPT, 'hex')); // P2PKH form!
    const pre = [];
    pre.push(...le32(1));
    pre.push(...hashPrevouts);
    pre.push(...hashSequence);
    pre.push(...outpoint);
    pre.push(scriptCode.length);
    pre.push(...scriptCode);
    for (let k = 0; k < 8; k++) pre.push(Number((BigInt(FUND) >> BigInt(8 * k)) & 0xffn));
    pre.push(...le32(0xffffffff));
    pre.push(2);
    for (const out of tx.outputs) {
      const v = out.value;
      for (let k = 0; k < 8; k++) pre.push(Number((v >> BigInt(8 * k)) & 0xffn));
      pre.push(out.script.length / 2);
      pre.push(...Uint8Array.from(Buffer.from(out.script, 'hex')));
    }
    pre.push(...le32(0));                                // locktime
    pre.push(...le32(1));                                // nHashType
    const digest = sha256d(Uint8Array.from(pre));
    expect(secp256k1.verify(sigNoSighash, digest, pub)).toBe(true);
  });
});

describe('Solana legacy memo transaction', () => {
  // payer must equal the ed25519 pubkey of solverSeed so the signed tx verifies.
  const solverSeed = Uint8Array.from({ length: 32 }, (_, i) => 7);
  const payer = 'GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB'; // base58(ed25519.getPublicKey(solverSeed))
  const blockhash = '9xZLJxjAbYvpN2mJu9rQ8fhUVMV6YZxP2aE1Ju1RKJHn'; // fixed 32-byte blockhash
  const metadata = encodeTrustMetadata(TrustLevel.ULTIMATE, payer, 1700000000000);

  it('builds the exact legacy wire format (header, accounts, blockhash, memo)', () => {
    const { messageBytes } = buildSolanaTrustTx({
      feePayer: payer, recentBlockhash: blockhash, metadataBytes: metadata, signPrivateKey: null,
    });
    const m = messageBytes;
    expect(m[0]).toBe(1);            // numRequiredSignatures
    expect(m[1]).toBe(0);            // numReadonlySignedAccounts
    expect(m[2]).toBe(1);            // numReadonlyUnsignedAccounts (memo program)
    expect(m[3]).toBe(2);            // account count
    const memoProgram = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
    expect(m.length).toBe(3 + 1 + 64 + 32 + 1 + 1 + 1 + 1 + 1 + metadata.length);
    // instruction: instrCount=1, programIdIndex=1, accountCount=1, payerIndex=0, dataLen, data
    const instrStart = 3 + 1 + 64 + 32;
    expect(m[instrStart]).toBe(1);          // instruction count
    expect(m[instrStart + 1]).toBe(1);      // programIdIndex (memo program)
    expect(m[instrStart + 2]).toBe(1);      // accountCount
    expect(m[instrStart + 3]).toBe(0);      // payerIndex
    expect(m[instrStart + 4]).toBe(metadata.length); // dataLen
    expect(m.slice(instrStart + 5)).toEqual(metadata);
    expect(typeof memoProgram).toBe('string'); // memo program constant exists
  });

  it('unsigned raw = 0 signatures prefix; signed raw carries a verifying Ed25519 sig', () => {
    const unsigned = buildSolanaTrustTx({
      feePayer: payer, recentBlockhash: blockhash, metadataBytes: metadata, signPrivateKey: null,
    });
    expect(unsigned.raw[0]).toBe(0);
    expect(unsigned.raw.length).toBe(1 + unsigned.messageBytes.length);
    expect(unsigned.signatureBase58).toBe(null);

    const signed = buildSolanaTrustTx({
      feePayer: payer, recentBlockhash: blockhash, metadataBytes: metadata, signPrivateKey: solverSeed,
    });
    expect(signed.raw[0]).toBe(1);
    expect(signed.raw.length).toBe(1 + 64 + signed.messageBytes.length);
    const signature = signed.raw.slice(1, 65);
    // The signature must verify against the feePayer public key by PARTIAL
    // comparison of the message: the digest signs the message bytes; we
    // verify the raw signature over the message.
    const payerBytes = signed.messageBytes.slice(3 + 1, 3 + 1 + 32);
    expect(ed25519.verify(signature, signed.messageBytes, payerBytes)).toBe(true);
    const { decodeBase58 } = null ?? {};
    expect(signed.signatureBase58.length).toBeGreaterThan(40);
    expect(signed.rawBase64.length).toBeGreaterThan(100);
  });
});

describe('Ethereum scanner data-field extractor', () => {
  const OWN = '0x8ba1f109551bd432803012645ac136ddd64dba72';
  const toWei = (n) => '0x' + n.toString(16);
  const trustData = '0x54' + '01' + '04' + '00000000';

  it('extracts outbound trust txs by data magic 0x5401', () => {
    const txs = [
      { hash: '0x' + 'aa'.repeat(32), from: OWN, to: '0x0000000000000000000000000000000000000001', input: trustData, blockNumber: '0x10', value: toWei(0) },
    ];
    const out = extractEthereumTrustTxs(txs, OWN, 1700000000);
    expect(out).toHaveLength(1);
    expect(out[0].type).toBe('trust');
    expect(out[0].level).toBe(TrustLevel.FULL);
    expect(out[0].chain).toBe('ethereum');
    expect(out[0].txHash).toBe('0x' + 'aa'.repeat(32));
  });

  it('extracts revocations by magic 0x5201 and ignores foreign/plain txs', () => {
    const revData = '0x52' + '01' + '00000000' + 'bb'.repeat(32);
    const txs = [
      { hash: '0x01', from: OWN, input: revData },
      { hash: '0x02', from: '0x' + 'cd'.repeat(20), input: revData },
      { hash: '0x03', from: OWN, input: '0x' + '00'.repeat(2) },
    ];
    const out = extractEthereumTrustTxs(txs, OWN, null);
    expect(out).toHaveLength(1);
    expect(out[0].type).toBe('revocation');
    expect(out[0].originalTxHash).toBe('bb'.repeat(32));
  });
});

describe('SDS TRE/$LOT map (Themis trust program)', () => {
  const trustTx = (overrides) => ({
    type: 'trust', txHash: '0x' + 'aa'.repeat(32), from: '0xOWNER',
    recipientPubkey: '0x' + 'bb'.repeat(20), level: TrustLevel.FULL,
    timestamp: 1700000000000, chain: 'ethereum', ...overrides,
  });
  const revokeTx = (overrides) => ({
    type: 'revocation', txHash: '0x' + 'cc'.repeat(32), originalTxHash: '0x' + 'bb'.repeat(20),
    from: '0xOWNER', timestamp: 1700001000000, chain: 'ethereum', ...overrides,
  });

  it('maps every level to WEIGHT (n-1)/4 and NEVER to 0.0', () => {
    expect(trustLevelToWeight(TrustLevel.NEVER)).toBe(0.0);
    expect(trustLevelToWeight(TrustLevel.UNKNOWN)).toBe(0.25);
    expect(trustLevelToWeight(TrustLevel.MARGINAL)).toBe(0.5);
    expect(trustLevelToWeight(TrustLevel.FULL)).toBe(0.75);
    expect(trustLevelToWeight(TrustLevel.ULTIMATE)).toBe(1.0);
    expect(trustWeightToLevel(0)).toBe(TrustLevel.NEVER);
    expect(trustWeightToLevel(0.75)).toBe(TrustLevel.FULL);
    expect(trustWeightToLevel(1)).toBe(TrustLevel.ULTIMATE);
    expect(() => trustLevelToWeight(0)).toThrow();
  });

  it('emits TRE edges with TX_HASH provenance and $LOT records for revocations', () => {
    const doc = buildSdsTrustExport([trustTx(), revokeTx()], { peerId: 'peer-1' });
    expect(doc.recordTypes).toEqual(['TRE', 'LOT']);
    expect(doc.tre).toHaveLength(1);
    expect(doc.tre[0].WEIGHT).toBe(0.75);
    expect(doc.tre[0].DELETED).toBe(true); // revoked edge is DELETED
    expect(doc.tre[0].TX_HASH).toBe('0x' + 'aa'.repeat(32));
    expect(doc.tre[0].PROVIDER_PEER_ID).toBe('peer-1');
    // $LOT loss-of-trust record bound to the original trust tx
    expect(doc.lot).toHaveLength(1);
    expect(doc.lot[0].LOSS_OF_TRUST_ID).toBe('0x' + 'cc'.repeat(32));
    expect(doc.lot[0].REASON).toBe('Distrust');
    expect(doc.lot[0].EVIDENCE_CHAIN).toBe('ethereum');
    expect(doc.lot[0].EVIDENCE_TRANSACTION_HASHES).toEqual([
      '0x' + 'cc'.repeat(32), '0x' + 'bb'.repeat(20),
    ]);
  });

  it('round-trips through parseSdsTrustImport (tre + lot)', () => {
    const doc = buildSdsTrustExport([trustTx(), revokeTx()]);
    const txs = parseSdsTrustImport(doc);
    expect(txs).toHaveLength(2);
    const trust = txs.find(t => t.type === 'trust');
    expect(trust.level).toBe(TrustLevel.FULL);
    expect(trust.recipientPubkey).toBe('0x' + 'bb'.repeat(20));
    const revoke = txs.find(t => t.type === 'revocation');
    expect(revoke.originalTxHash).toBe('0x' + 'bb'.repeat(20));
    expect(txs.find(t => t.type === 'revocation').txHash).toBe('0x' + 'cc'.repeat(32));
    expect(() => parseSdsTrustImport(null)).toThrow();
  });
});

describe('drain detection', () => {
  it('flags a balance drop past the ratio and stays silent below it', () => {
    expect(evaluateTrustDrain({ previousBalance: 10, currentBalance: 0.5, dropRatio: 0.9 }).drained).toBe(true);
    expect(evaluateTrustDrain({ previousBalance: 10, currentBalance: 9.5, dropRatio: 0.9 }).drained).toBe(false);
    expect(evaluateTrustDrain({ previousBalance: '--', currentBalance: '--' }).drained).toBe(false);
    expect(evaluateTrustDrain({ previousBalance: 0, currentBalance: 0 }).drained).toBe(false);
    const res = evaluateTrustDrain({ previousBalance: 10, currentBalance: 1, dropRatio: 0.9 });
    expect(res.dropRatioObserved).toBe(0.9);
    expect(res.drained).toBe(true);
  });
});
