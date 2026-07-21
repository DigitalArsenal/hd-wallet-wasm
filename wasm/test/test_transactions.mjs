/**
 * HD Wallet WASM - Transaction Builder Tests
 *
 * Ensures Bitcoin/Ethereum tx builders match the underlying C ABI and
 * can build, sign, serialize, parse, and compute txids/hashes.
 */

import init, {
  Curve,
  Network,
  BitcoinAddressType,
  BitcoinScriptType,
} from '../src/index.mjs';

import { test, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();

test('Bitcoin tx: build, sign, serialize, parse, and compute txid', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const inputTxid = '00'.repeat(32);
  const inputAmount = 100000n;
  const outputAmount = 90000n;
  const expectedFee = inputAmount - outputAmount;

  const outAddr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET);

  const tx = wallet.bitcoin.tx.create()
    .addInput({
      txid: inputTxid,
      vout: 0,
      amount: inputAmount,
      scriptType: BitcoinScriptType.P2WPKH,
      pubkey: pub,
    })
    .addOutput(outAddr, outputAmount, Network.MAINNET)
    .sign(priv);

  const raw = tx.serialize();
  assert(raw.length > 0, 'Expected non-empty serialized transaction');

  const txid = tx.getTxid();
  assert(/^[0-9a-fA-F]{64}$/.test(txid), 'Expected 64-hex txid');

  assert(tx.getSize() > 0, 'Expected tx size');
  assert(tx.getVsize() > 0, 'Expected tx vsize');
  assertEqual(tx.getFee(), expectedFee, 'Expected fee = sum(inputs) - sum(outputs)');
  assertEqual(tx.validate(), true);

  const parsed = wallet.bitcoin.tx.parse(raw);
  assertEqual(parsed.getTxid().toLowerCase(), txid.toLowerCase(), 'Parsed tx should have same txid');

  parsed.destroy();
  tx.destroy();
});

test('Ethereum tx (EIP-1559): build, sign, serialize, parse, and compute hash', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const to = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

  const tx = wallet.ethereum.tx.createEIP1559({
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 1_000_000_000n,
    maxFeePerGas: 2_000_000_000n,
    gasLimit: 21_000n,
    to,
    value: 1n,
  }).sign(priv);

  const raw = tx.serialize();
  assert(raw.length > 0, 'Expected non-empty serialized transaction');

  const hash = tx.getHash();
  assert(/^0x[0-9a-fA-F]{64}$/.test(hash), 'Expected 0x-prefixed 32-byte tx hash');

  const parsed = wallet.ethereum.tx.parse(raw);
  assertEqual(parsed.getHash().toLowerCase(), hash.toLowerCase(), 'Parsed tx should have same hash');

  parsed.destroy();
  tx.destroy();
});

test('Bitcoin tx (P2PKH legacy): build, sign, serialize, parse', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const inputTxid = 'aa'.repeat(32);
  const inputAmount = 50000n;
  const outputAmount = 40000n;

  const outAddr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.MAINNET);

  const tx = wallet.bitcoin.tx.create()
    .addInput({
      txid: inputTxid,
      vout: 0,
      amount: inputAmount,
      scriptType: BitcoinScriptType.P2PKH,
      pubkey: pub,
    })
    .addOutput(outAddr, outputAmount, Network.MAINNET)
    .sign(priv);

  const raw = tx.serialize();
  assert(raw.length > 0, 'Expected non-empty serialized legacy transaction');

  const txid = tx.getTxid();
  assert(/^[0-9a-fA-F]{64}$/.test(txid), 'Expected 64-hex txid for legacy tx');

  assertEqual(tx.getFee(), inputAmount - outputAmount, 'Legacy tx fee should match');
  assertEqual(tx.validate(), true, 'Legacy tx should validate');

  const parsed = wallet.bitcoin.tx.parse(raw);
  assertEqual(parsed.getTxid().toLowerCase(), txid.toLowerCase(), 'Parsed legacy tx should have same txid');

  parsed.destroy();
  tx.destroy();
});

test('Ethereum tx (legacy): build, sign, serialize, parse via create()', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');

  const tx = wallet.ethereum.tx.create({ chainId: 1 }).sign(priv);

  const raw = tx.serialize();
  assert(raw.length > 0, 'Expected non-empty serialized legacy ETH transaction');

  const hash = tx.getHash();
  assert(/^0x[0-9a-fA-F]{64}$/.test(hash), 'Expected 0x-prefixed 32-byte hash for legacy tx');

  const parsed = wallet.ethereum.tx.parse(raw);
  assertEqual(parsed.getHash().toLowerCase(), hash.toLowerCase(), 'Parsed legacy ETH tx should have same hash');

  parsed.destroy();
  tx.destroy();
});

test('Bitcoin tx: multi-input (2 inputs, 2 outputs)', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const txid1 = '11'.repeat(32);
  const txid2 = '22'.repeat(32);
  const inputAmount1 = 60000n;
  const inputAmount2 = 40000n;
  const outputAmount1 = 80000n;
  const outputAmount2 = 15000n;
  const expectedFee = (inputAmount1 + inputAmount2) - (outputAmount1 + outputAmount2);

  const addr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET);

  const tx = wallet.bitcoin.tx.create()
    .addInput({
      txid: txid1,
      vout: 0,
      amount: inputAmount1,
      scriptType: BitcoinScriptType.P2WPKH,
      pubkey: pub,
    })
    .addInput({
      txid: txid2,
      vout: 1,
      amount: inputAmount2,
      scriptType: BitcoinScriptType.P2WPKH,
      pubkey: pub,
    })
    .addOutput(addr, outputAmount1, Network.MAINNET)
    .addOutput(addr, outputAmount2, Network.MAINNET)
    .sign(priv);

  const raw = tx.serialize();
  assert(raw.length > 0, 'Expected non-empty multi-input serialized transaction');

  const txid = tx.getTxid();
  assert(/^[0-9a-fA-F]{64}$/.test(txid), 'Expected 64-hex txid for multi-input tx');

  assertEqual(tx.getFee(), expectedFee, 'Multi-input tx fee should equal sum(inputs) - sum(outputs)');
  assert(tx.getSize() > 0, 'Expected positive size for multi-input tx');
  assert(tx.getVsize() > 0, 'Expected positive vsize for multi-input tx');
  assertEqual(tx.validate(), true, 'Multi-input tx should validate');

  const parsed = wallet.bitcoin.tx.parse(raw);
  assertEqual(parsed.getTxid().toLowerCase(), txid.toLowerCase(), 'Parsed multi-input tx should have same txid');

  parsed.destroy();
  tx.destroy();
});

test('Bitcoin tx: serialize -> parse -> re-serialize round-trip', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const inputTxid = 'bb'.repeat(32);
  const outAddr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET);

  const tx = wallet.bitcoin.tx.create()
    .addInput({
      txid: inputTxid,
      vout: 0,
      amount: 100000n,
      scriptType: BitcoinScriptType.P2WPKH,
      pubkey: pub,
    })
    .addOutput(outAddr, 90000n, Network.MAINNET)
    .sign(priv);

  const raw1 = tx.serialize();
  const hex1 = bytesToHex(raw1);

  const parsed = wallet.bitcoin.tx.parse(raw1);
  const raw2 = parsed.serialize();
  const hex2 = bytesToHex(raw2);

  assertEqual(hex1, hex2, 'Re-serialized bytes should match original serialization');

  parsed.destroy();
  tx.destroy();
});

test('Ethereum tx (EIP-1559): serialize -> parse -> re-serialize round-trip', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const to = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

  const tx = wallet.ethereum.tx.createEIP1559({
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 1_000_000_000n,
    maxFeePerGas: 2_000_000_000n,
    gasLimit: 21_000n,
    to,
    value: 1n,
  }).sign(priv);

  const raw1 = tx.serialize();
  const hex1 = bytesToHex(raw1);

  const parsed = wallet.ethereum.tx.parse(raw1);
  const raw2 = parsed.serialize();
  const hex2 = bytesToHex(raw2);

  assertEqual(hex1, hex2, 'Re-serialized ETH tx bytes should match original');

  parsed.destroy();
  tx.destroy();
});
