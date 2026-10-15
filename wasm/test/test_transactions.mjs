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

  // A legacy transfer needs a recipient (2.1.1): without one it used to sign
  // a transaction to 0x00..00. The declared fields now reach the signed bytes.
  const recipientless = wallet.ethereum.tx.create({ chainId: 1 });
  let recipientlessSigned = true;
  try {
    recipientless.sign(priv);
  } catch {
    recipientlessSigned = false;
  } finally {
    recipientless.destroy();
  }
  assertEqual(recipientlessSigned, false, 'A legacy tx without a recipient must not sign');

  const tx = wallet.ethereum.tx.create({
    chainId: 1,
    nonce: 9,
    gasPrice: 20_000_000_000n,
    gasLimit: 21_000n,
    to: '0x3535353535353535353535353535353535353535',
    value: 10n ** 18n,
  }).sign(hexToBytes('46'.repeat(32)));

  const raw = tx.serialize();
  // The EIP-155 example transaction (https://eips.ethereum.org/EIPS/eip-155).
  assertEqual(bytesToHex(raw),
    'f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef6134'
    + '0bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3'
    + 'dc64214b297fb1966a3b6d83', 'EIP-155 example signed bytes');

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

// --- Ethereum recipient and value (2.1.1) -----------------------------------
//
// Up to 2.1.0 an unparsable 'to' left the transaction with 20 zero bytes as
// its recipient and it signed a value transfer to 0x00..00, and a value of
// 2^64 wei or more (~18.45 ETH) wrapped modulo 2^64.

const ETH_PRIV = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
const ETH_TO = '0x52908400098527886E0F7030069857D2E4169EE7';
const ethParams = (overrides = {}) => ({
  chainId: 1,
  nonce: 7,
  maxPriorityFeePerGas: 2_000_000_000n,
  maxFeePerGas: 30_000_000_000n,
  gasLimit: 21_000n,
  to: ETH_TO,
  value: 500_000_000_000_000_000n,
  ...overrides,
});

function expectThrow(fn, label) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  assert(threw, `${label}: expected a throw`);
}

for (const [label, to] of [
  ['ENS name', 'vitalik.eth'],
  ['39 hex digits', '0x52908400098527886E0F7030069857D2E4169EE'],
  ['41 hex digits', '0x52908400098527886E0F7030069857D2E4169EE7a'],
  ['extra character', '0x52908400098527886E0F7030069857D2E4169EE7x'],
  ['non-hex character', '0x52908400098527886E0F7030069857D2E4169EEg'],
  ['Bitcoin address', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'],
  ['Solana address', '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV'],
]) {
  test(`Ethereum tx: ${label} as recipient is refused, never sent to 0x00..00`, () => {
    let tx = null;
    let signed = null;
    try {
      tx = wallet.ethereum.tx.createEIP1559(ethParams({ to }));
      signed = bytesToHex(tx.sign(ETH_PRIV).serialize());
    } catch {
      // refused: the expected outcome
    } finally {
      tx?.destroy();
    }
    assertEqual(signed, null, `${label} produced a signed transaction`);
  });
}

test('Ethereum tx: a transfer with no recipient does not sign or serialize', () => {
  for (const to of [undefined, null, '']) {
    const tx = wallet.ethereum.tx.createEIP1559(ethParams({ to }));
    try {
      expectThrow(() => tx.sign(ETH_PRIV), `sign with to=${JSON.stringify(to)}`);
      expectThrow(() => tx.serialize(), `serialize with to=${JSON.stringify(to)}`);
      expectThrow(() => tx.getHash(), `hash with to=${JSON.stringify(to)}`);
    } finally {
      tx.destroy();
    }
  }
});

test('Ethereum tx: 20 ETH serializes as 20 ETH (no wrap modulo 2^64)', () => {
  const twentyEth = 20n * 10n ** 18n; // 0x01158e460913d00000
  const tx = wallet.ethereum.tx.createEIP1559(ethParams({ value: twentyEth })).sign(ETH_PRIV);
  try {
    const raw = bytesToHex(tx.serialize());
    const field = '94' + ETH_TO.slice(2).toLowerCase() + '89' + '01158e460913d00000';
    assert(raw.includes(field), `to and value fields not found in ${raw}`);
    const parsed = wallet.ethereum.tx.parse(hexToBytes(raw));
    assertEqual(bytesToHex(parsed.serialize()), raw, 'parse round-trip');
    parsed.destroy();
  } finally {
    tx.destroy();
  }

  const atLimit = wallet.ethereum.tx.createEIP1559(ethParams({ value: 1n << 64n })).sign(ETH_PRIV);
  try {
    assert(bytesToHex(atLimit.serialize()).includes('89' + '01' + '00'.repeat(8)), '2^64 wei encodes as 9 bytes');
  } finally {
    atLimit.destroy();
  }
  const max = wallet.ethereum.tx.createEIP1559(ethParams({ value: (1n << 256n) - 1n })).sign(ETH_PRIV);
  try {
    assert(bytesToHex(max.serialize()).includes('a0' + 'ff'.repeat(32)), '2^256 - 1 wei encodes in full');
  } finally {
    max.destroy();
  }
});

test('Ethereum tx: out-of-range integers are refused, not wrapped', () => {
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ value: 1n << 256n })), 'value 2^256');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ value: -1n })), 'value -1');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ value: 1.5 })), 'value 1.5');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ nonce: 1n << 64n })), 'nonce 2^64');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ gasLimit: (1n << 64n) + 21_000n })), 'gasLimit 2^64 + 21000');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ maxFeePerGas: -2n })), 'maxFeePerGas -2');
  expectThrow(() => wallet.ethereum.tx.createEIP1559(ethParams({ chainId: 2 ** 64 })), 'chainId 2^64');
});
