// Raw Bitcoin transactions for the Send tests, built and hashed here
// independently of the wallet code (legacy and segwit serialization).

import { sha256 } from '@noble/hashes/sha256';

import { bytesToHex } from '../../src/send-safety.js';

// A minimal raw transaction builder for the UTXO tests (legacy and segwit
// serialization), so the expected txids are computed here, independently.
function u32le(n) {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}
function u64le(v) {
  const out = [];
  for (let i = 0n; i < 8n; i += 1n) out.push(Number((v >> (8n * i)) & 0xffn));
  return out;
}
export function rawTx({ outputs, witness = false }) {
  const input = [...new Array(32).fill(0xab), ...u32le(1), 0, ...u32le(0xffffffff)];
  const outs = outputs.flatMap(({ value, script }) => [...u64le(value), script.length, ...script]);
  const body = [1, ...input, outputs.length, ...outs];
  const stripped = Uint8Array.from([...u32le(2), ...body, ...u32le(0)]);
  const full = witness
    ? Uint8Array.from([...u32le(2), 0x00, 0x01, ...body, 1, 1, 0x42, ...u32le(0)])
    : stripped;
  const txid = bytesToHex(sha256(sha256(stripped)).reverse());
  return { hex: bytesToHex(full), txid };
}

