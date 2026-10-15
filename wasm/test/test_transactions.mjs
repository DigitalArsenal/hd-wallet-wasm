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

import { test, assert, assertEqual, assertThrows, bytesToHex, hexToBytes } from './test_all.mjs';

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
  const recipientless = wallet.ethereum.tx.create({ chainId: 1, nonce: 0 });
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
  // 2.1.1 round 2: a second prefix left 19 bytes and an uninitialized last
  // byte, which was signed as the recipient's.
  ['0x0x + 38 hex digits', '0x0x52908400098527886E0F7030069857D2E4169E'],
  ['0X0x + 38 hex digits', '0X0x52908400098527886E0F7030069857D2E4169E'],
  ['0x0X + 38 hex digits', '0x0X52908400098527886E0F7030069857D2E4169E'],
  ['a NUL and garbage after the address', `${'0x52908400098527886E0F7030069857D2E4169EE7'}\u0000garbage`],
  ['an unpaired surrogate after the address', `${'0x52908400098527886E0F7030069857D2E4169EE7'}\uD800`],
  ['a broken EIP-55 checksum', '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'],
  ['the zero address', '0x0000000000000000000000000000000000000000'],
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

// --- Recipient parsing (2.1.1 round 2) ---------------------------------------
//
// The only accepted recipient: exactly 40 ASCII hex digits after at most one
// 0x/0X; mixed case must be the EIP-55 checksum; never the zero address. The
// reference below is the rule; every input goes through createEIP1559 and
// legacy create() and, when accepted, must sign to exactly those 20 bytes.

const EIP55_EXAMPLES = [
  '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  'fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  'dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
];

function referenceRecipient(input) {
  const body = /^0[xX]/.test(input) ? input.slice(2) : input;
  if (!/^[0-9a-fA-F]{40}$/.test(body)) return null;
  if (/^0{40}$/.test(body)) return null;
  if (/[a-f]/.test(body) && /[A-F]/.test(body) && !EIP55_EXAMPLES.includes(body)) return null;
  return body.toLowerCase();
}

function signedRecipient(build, to) {
  let tx = null;
  try {
    tx = build(to);
    const raw = bytesToHex(tx.sign(ETH_PRIV).serialize());
    return raw;
  } catch {
    return null;
  } finally {
    tx?.destroy();
  }
}

const RECIPIENT_BUILDERS = [
  ['createEIP1559', (to) => wallet.ethereum.tx.createEIP1559(ethParams({ to }))],
  ['create (legacy)', (to) => wallet.ethereum.tx.create({ chainId: 1, nonce: 7, gasPrice: 1n, gasLimit: 21_000n, to, value: 1n })],
];

function escapeForLabel(input) {
  return JSON.stringify(input).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function checkRecipient(input, problems, builders = RECIPIENT_BUILDERS) {
  const expected = referenceRecipient(input);
  for (const [name, build] of builders) {
    const raw = signedRecipient(build, input);
    if (expected === null && raw !== null) {
      problems.push(`${name}: ${escapeForLabel(input)} signed (${raw.slice(0, 80)}...)`);
    } else if (expected !== null && raw === null) {
      problems.push(`${name}: ${escapeForLabel(input)} refused`);
    } else if (expected !== null && !raw.includes('94' + expected)) {
      problems.push(`${name}: ${escapeForLabel(input)} signed to a different recipient`);
    }
  }
}

// Pieces an address could be confused with: ASCII hex, prefixes, whitespace,
// NUL, other scripts' digits, look-alike letters, invisible characters and an
// unpaired surrogate.
const RECIPIENT_PIECES = [
  '0', '1', '7', '9', 'a', 'f', 'A', 'F', 'e', 'E', '0x', '0X', 'x', 'X', 'g', 'G', '-', '+',
  ' ', '\t', '\n', '\r', '\u0000',
  '０', '１', 'ａ', // fullwidth 0, 1, a
  '٣', '५', '²', // Arabic-Indic 3, Devanagari 5, superscript 2
  ' ', '​', '﻿', // no-break space, zero-width space, BOM
  'А', 'с', // Cyrillic A, es
  '\uD800', '\uDC00', '\u{1D7CE}', // unpaired surrogates, MATHEMATICAL BOLD DIGIT ZERO
];

test('Ethereum tx: recipient accepted forms sign to exactly that address', () => {
  const problems = [];
  for (const to of [
    '0x52908400098527886E0F7030069857D2E4169EE7',
    '0X52908400098527886E0F7030069857D2E4169EE7',
    '52908400098527886e0f7030069857d2e4169ee7',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed',
    '0x0000000000000000000000000000000000000001',
  ]) {
    assert(referenceRecipient(to) !== null, `reference accepts ${to}`);
    checkRecipient(to, problems);
  }
  assertEqual(problems.join('\n'), '', 'accepted forms');
});

test('Ethereum tx: recipient fuzz (prefixes, whitespace, unicode digits, lengths)', () => {
  const problems = [];
  let cases = 0;
  const run = (input, builders) => { cases++; checkRecipient(input, problems, builders); };
  const valid = '52908400098527886e0f7030069857d2e4169ee7';
  const prefixes = ['', '0x', '0X', '0x0x', '0X0x', '0x0X', '00x', 'x', '0', '0xx', ' 0x', '0x ', '\t0x',
    '+0x', '-0x', '０x', '0ｘ', '﻿0x'];
  const suffixes = ['', ' ', '\n', '\r\n', '\t', ' ', '​', '\u0000', '\u0000garbage', '\uD800', '0', '00'];
  const bodies = [];
  for (let len = 36; len <= 44; len++) bodies.push((valid + 'a'.repeat(8)).slice(0, len));
  for (const known of EIP55_EXAMPLES) bodies.push(known, known.toLowerCase(), known.toUpperCase());
  for (const prefix of prefixes) {
    for (const body of bodies) {
      for (const suffix of suffixes) run(prefix + body + suffix, RECIPIENT_BUILDERS.slice(0, 1));
    }
  }

  // One edit of each EIP-55 example at every position, through both builders.
  for (const known of EIP55_EXAMPLES) {
    const base = '0x' + known;
    for (let at = 0; at <= base.length; at++) {
      if (at < base.length) {
        run(base.slice(0, at) + base.slice(at + 1));
        const c = base[at];
        const flipped = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase();
        run(base.slice(0, at) + flipped + base.slice(at + 1));
      }
      for (const piece of RECIPIENT_PIECES) {
        run(base.slice(0, at) + piece + base.slice(at), RECIPIENT_BUILDERS.slice(0, 1));
        if (at < base.length) run(base.slice(0, at) + piece + base.slice(at + 1), RECIPIENT_BUILDERS.slice(0, 1));
      }
    }
  }

  // Random strings (seeded): pieces, and lowercase hex of 0..50 digits.
  let state = 0x2545F491;
  const next = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  for (let i = 0; i < 3000; i++) {
    let s = next() & 1 ? '0x' : '';
    const n = next() % 49;
    for (let k = 0; k < n; k++) s += RECIPIENT_PIECES[next() % RECIPIENT_PIECES.length];
    run(s, RECIPIENT_BUILDERS.slice(0, 1));
  }
  for (let i = 0; i < 3000; i++) {
    let s = next() & 1 ? '0x' : '';
    const n = next() & 3 ? 40 : next() % 51;
    for (let k = 0; k < n; k++) s += '0123456789abcdef'[next() % 16];
    run(s, RECIPIENT_BUILDERS.slice(0, 1));
  }

  console.log(`    (${cases} recipient inputs)`);
  assert(cases > 15000, `ran ${cases} inputs`);
  assertEqual(problems.slice(0, 20).join('\n'), '', `${problems.length} recipient inputs disagree with the rule`);
});

test('Ethereum tx: the zero address and a double prefix are refused when the transaction is built', () => {
  // The C setter refuses both, so the wrapper throws at build time.
  for (const to of ['0x0000000000000000000000000000000000000000', '0x0x52908400098527886E0F7030069857D2E4169E']) {
    assertThrows(() => wallet.ethereum.tx.createEIP1559(ethParams({ to })), `createEIP1559 to ${to}`);
    assertThrows(() => wallet.ethereum.tx.create({ chainId: 1, nonce: 7, gasLimit: 21_000n, to, value: 1n }), `create to ${to}`);
  }
});

// ---------------------------------------------------------------------------
// 2.1.2: Ethereum nonce and chainId are required
// ---------------------------------------------------------------------------
// A missing nonce signed nonce 0 and a missing chainId (legacy) chain 1; chain
// 0 signed a pre-EIP-155 transaction valid on every chain. Both are required,
// an explicit nonce 0 is a nonce, and chainId is at least 1.

const EIP155_NONCE0 = 'f86c808504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008026a0f3d5a389'
  + '0fbcbd1f1f7c9affab932af4062e4f03e3ac8cea31ed36f705390da6a03cef06a6742d436a0c36ac89ca98197d44e12292'
  + '5ce59947d398172d97ce41cb';
const eip155Params = (overrides = {}) => ({
  chainId: 1,
  nonce: 0,
  gasPrice: 20_000_000_000n,
  gasLimit: 21_000n,
  to: '0x3535353535353535353535353535353535353535',
  value: 10n ** 18n,
  ...overrides,
});

// The signed bytes, or null when the builder or the signer refuses.
function signedOrNull(build) {
  let tx = null;
  try {
    tx = build();
    return bytesToHex(tx.sign(hexToBytes('46'.repeat(32))).serialize());
  } catch {
    return null;
  } finally {
    tx?.destroy();
  }
}

test('Ethereum tx: a missing nonce or chainId is refused, never defaulted', () => {
  const builders = [
    ['create', (o) => () => wallet.ethereum.tx.create(eip155Params(o))],
    ['createEIP1559', (o) => () => wallet.ethereum.tx.createEIP1559(ethParams(o))],
  ];
  const problems = [];
  for (const [name, build] of builders) {
    for (const [label, overrides] of [
      ['no nonce', { nonce: undefined }],
      ['nonce null', { nonce: null }],
      ['no chainId', { chainId: undefined }],
      ['chainId null', { chainId: null }],
      ['chainId 0', { chainId: 0 }],
      ['chainId 0n', { chainId: 0n }],
      ['chainId "0"', { chainId: '0' }],
    ]) {
      const signed = signedOrNull(build(overrides));
      if (signed !== null) problems.push(`${name} ${label} signed ${signed.slice(0, 24)}...`);
    }
    // Without the property at all (not only undefined).
    for (const key of ['nonce', 'chainId']) {
      const params = name === 'create' ? eip155Params() : ethParams();
      delete params[key];
      const signed = signedOrNull(() => wallet.ethereum.tx[name](params));
      if (signed !== null) problems.push(`${name} without ${key} signed ${signed.slice(0, 24)}...`);
    }
  }
  assertEqual(problems.join('\n'), '', 'every missing nonce/chainId must be refused');

  // An explicit nonce 0 signs: the EIP-155 example transaction at nonce 0.
  assertEqual(signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ nonce: 0 }))), EIP155_NONCE0, 'nonce 0 (number)');
  assertEqual(signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ nonce: 0n }))), EIP155_NONCE0, 'nonce 0n');
  assert(signedOrNull(() => wallet.ethereum.tx.createEIP1559(ethParams({ nonce: 0 }))) !== null, 'EIP-1559 nonce 0 signs');
});

test('Ethereum tx: each field is read once (a Uint8Array with a lying length is refused or signs its own bytes)', () => {
  const data = hexToBytes('deadbeef');
  const reference = signedOrNull(() => wallet.ethereum.tx.createEIP1559(ethParams({ data })));
  assert(reference !== null && reference.includes('84deadbeef'), 'reference transaction carries 0x84 deadbeef');

  // A subclass whose length claims 64 bytes: 60 of them would come from the heap.
  class LyingLength extends Uint8Array {
    get length() { return 64; }
  }
  // It is refused (its length is not its own) or signs exactly its own bytes.
  const lying = new LyingLength(data);
  const lyingEip1559 = signedOrNull(() => wallet.ethereum.tx.createEIP1559(ethParams({ data: lying })));
  assert(lyingEip1559 === null || lyingEip1559 === reference, 'createEIP1559 with a lying length');
  const lyingLegacy = signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ data: lying })));
  assert(lyingLegacy === null || lyingLegacy === signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ data }))),
    'create with a lying length');

  // A getter that answers one array when checked and another, longer one later.
  let reads = 0;
  const params = ethParams();
  Object.defineProperty(params, 'data', {
    enumerable: true,
    get() { reads++; return reads === 1 ? data : new Uint8Array(4096).fill(0x41); },
  });
  assertEqual(signedOrNull(() => wallet.ethereum.tx.createEIP1559(params)), reference, 'data getter read once');
  assertEqual(reads, 1, 'params.data read exactly once');

  // The same for the recipient: the address checked is the address signed.
  let toReads = 0;
  const toParams = ethParams();
  Object.defineProperty(toParams, 'to', {
    enumerable: true,
    get() { toReads++; return toReads === 1 ? ETH_TO : '0x000000000000000000000000000000000000dEaD'; },
  });
  assertEqual(signedOrNull(() => wallet.ethereum.tx.createEIP1559(toParams)),
    signedOrNull(() => wallet.ethereum.tx.createEIP1559(ethParams())), 'to getter read once');
  assertEqual(toReads, 1, 'params.to read exactly once');
});

// ---------------------------------------------------------------------------
// 2.1.2: a Bitcoin output pays the script its address encodes (BIP-350)
// ---------------------------------------------------------------------------
// The type came from the program length alone: a witness-v1 address with a
// 20-byte program paid P2WPKH 0014..., witness v2..16 with 32 bytes paid P2WSH
// 0020... (a burn). Only v0/20, v0/32 and v1/32 are paid now. Vectors: BIP-350
// valid and invalid segwit addresses, and v1/20, v2/32, v3/20 encoded with
// BIP-350's reference encoder.

const BIP350_OUTPUTS = [
  // [address, network, scriptPubKey or null (refused)]
  ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', Network.MAINNET, '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
  ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', Network.TESTNET,
    '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
  ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', Network.MAINNET, null],
  ['BC1SW50QGDZ25J', Network.MAINNET, null],
  ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', Network.MAINNET, null],
  ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', Network.TESTNET,
    '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', Network.TESTNET,
    '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', Network.MAINNET,
    '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
  // Valid encodings this wallet does not pay (before 2.1.2: 0014..., 0020..., 0014..., 0020..., 0014...).
  ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kj9wkru', Network.MAINNET, null],
  ['bc1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq2tdauy', Network.MAINNET, null],
  ['bc1rw508d6qejxtdg4y5r3zarvary0c5xw7kysfqe2', Network.MAINNET, null],
  ['tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqarmjxt', Network.TESTNET, null],
  ['tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kcr49c0', Network.TESTNET, null],
  // BIP-350 invalid segwit addresses.
  ...[
    'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
    'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
    'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
    'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
    'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
    'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
    'bc1pw5dgrnzv',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
    'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
    'bc1gmk9yu',
  ].map((address) => [address, address.toLowerCase().startsWith('tb') ? Network.TESTNET : Network.MAINNET, null]),
];

// The serialized output (8-byte amount, script length, script) or null when
// addOutput refuses the address.
function paidScript(address, network) {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  let tx = null;
  try {
    tx = wallet.bitcoin.tx.create().addInput({
      txid: '11'.repeat(32), vout: 0, amount: 100_000n, scriptType: BitcoinScriptType.P2WPKH, pubkey: pub,
    });
    try {
      tx.addOutput(address, 54_321n, network);
    } catch {
      return null;
    }
    const raw = bytesToHex(tx.sign(priv).serialize());
    const amount = '31d4000000000000'; // 54321 little-endian
    const at = raw.indexOf(amount);
    assert(at >= 0, `${address}: output amount in the serialized transaction`);
    const length = parseInt(raw.slice(at + 16, at + 18), 16);
    return raw.slice(at + 18, at + 18 + 2 * length);
  } finally {
    tx?.destroy();
  }
}

test('Bitcoin tx: addOutput pays only v0/20, v0/32 and v1/32 SegWit addresses (BIP-350)', () => {
  const problems = [];
  for (const [address, network, script] of BIP350_OUTPUTS) {
    const paid = paidScript(address, network);
    if (paid !== script) problems.push(`${address}: paid ${paid ?? 'nothing (refused)'}, expected ${script ?? 'a refusal'}`);
    // The validator and decoder agree with addOutput.
    if (wallet.bitcoin.validateAddress(address, network) !== (script !== null)) problems.push(`${address}: validateAddress disagrees`);
    let decoded = null;
    try { decoded = wallet.bitcoin.decodeAddress(address); } catch { /* refused */ }
    if ((decoded !== null) !== (script !== null)) problems.push(`${address}: decodeAddress disagrees`);
  }
  assertEqual(problems.join('\n'), '', 'every output pays the script its address encodes, or is refused');
});

// ---------------------------------------------------------------------------
// 2.1.2 (round 2): the output's network, the chain ID bound, unsigned legacy
// ---------------------------------------------------------------------------

test('Bitcoin tx: addOutput pays only addresses of the transaction\'s network', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const addresses = {
    [Network.MAINNET]: [
      wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET),
      wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.MAINNET),
    ],
    [Network.TESTNET]: [
      wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.TESTNET),
      wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.TESTNET),
    ],
  };
  const pays = (address, network) => {
    const tx = wallet.bitcoin.tx.create();
    try {
      tx.addOutput(address, 1000n, network);
      return true;
    } catch {
      return false;
    } finally {
      tx.destroy();
    }
  };
  const problems = [];
  for (const network of [Network.MAINNET, Network.TESTNET]) {
    for (const [addressNetwork, list] of Object.entries(addresses)) {
      for (const address of list) {
        const expected = Number(addressNetwork) === network;
        if (pays(address, network) !== expected) {
          problems.push(`network ${network} ${expected ? 'refused' : 'paid'} ${address}`);
        }
      }
    }
  }
  // The default is mainnet; other network ids (regtest included) are refused.
  if (pays(addresses[Network.TESTNET][0])) problems.push('default (mainnet) paid a testnet address');
  if (!pays(addresses[Network.MAINNET][0])) problems.push('default (mainnet) refused a mainnet address');
  for (const network of [2, 3, -1]) {
    if (pays(addresses[Network.TESTNET][0], network)) problems.push(`network ${network} paid a testnet address`);
  }
  if (pays('bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080', Network.TESTNET)) problems.push('paid a regtest address');
  if (wallet.bitcoin.validateAddress(addresses[Network.TESTNET][0], 2)) problems.push('validateAddress(network 2) read as testnet');
  assertEqual(problems.join('\n'), '', 'outputs follow the transaction network');
});

test('Ethereum tx: chainId above EIP-2294\'s bound is refused (v would wrap)', () => {
  const MAX = 9223372036854775771n; // floor(MAX_UINT64 / 2) - 36
  for (const chainId of [(1n << 63n) + 1n, MAX + 1n, (1n << 64n) - 1n]) {
    assertEqual(signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ chainId }))), null, `legacy chainId ${chainId}`);
    assertEqual(signedOrNull(() => wallet.ethereum.tx.createEIP1559(ethParams({ chainId }))), null, `EIP-1559 chainId ${chainId}`);
  }
  const atBound = signedOrNull(() => wallet.ethereum.tx.create(eip155Params({ chainId: MAX })));
  assert(atBound !== null, 'the bound itself signs');
  const parsed = wallet.ethereum.tx.parse(hexToBytes(atBound));
  parsed.destroy();
});

test('Ethereum tx: an unsigned legacy transaction serializes in its EIP-155 signing form and signs after parsing', () => {
  const unsignedTx = wallet.ethereum.tx.create(eip155Params({ nonce: 9 }));
  let raw;
  try {
    raw = unsignedTx.serialize();
  } finally {
    unsignedTx.destroy();
  }
  // EIP-155's signing data: chainId 1, 0, 0 where v, r, s go.
  assertEqual(bytesToHex(raw),
    'ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080',
    'unsigned legacy bytes');
  const parsed = wallet.ethereum.tx.parse(raw);
  try {
    assertEqual(bytesToHex(parsed.sign(hexToBytes('46'.repeat(32))).serialize()),
      'f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef6134'
      + '0bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3'
      + 'dc64214b297fb1966a3b6d83', 'parsed then signed: the EIP-155 example');
  } finally {
    parsed.destroy();
  }
});

// ---------------------------------------------------------------------------
// 2.1.2 (round 3): strict transaction parsing, checked against ethers 6.13.4
// ---------------------------------------------------------------------------
// RLP integers kept their low 64 bits and leading zeros: parse then sign of an
// unsigned legacy transaction for chain 2^64 + 1 signed for chain 1, a 9-byte
// nonce signed as nonce 9. Vectors from ethers 6.13.4 (Transaction,
// Wallet.signTransaction, encodeRlp) and hand-made non-canonical forms.

const ETHERS_VECTORS = [
  // [name, ethers unsignedSerialized, ethers signed serialized] (key 0x46..46)
  ['legacy', 'ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080',
    'f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83'],
  ['eip2930', '01eb01098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c0',
    '01f86e01098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0a55f6a8616e3d6d2f09ee945cdad2a21a7d357225fcfc46df9e8421420954f43a01d7bd8c3892f4271f397c91e6c4216fb4284bc75c8d320b952bdb069aaa8120e'],
  ['eip1559', '02f00109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0',
    '02f8730109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0ad4241a480b4069450d9bd1823a3afb8bd5a697e2135056f13fc85778785a013a0782c2fc38f01d18de96e4f5caeb077484ef6d844f2ce873a475515552460c075'],
  ['legacyChain137', 'ed098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008081898080',
    'f86e098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080820136a00d02a2ce7ed82574448f5581c0c45a2eb0b6e2ccf6971eff1dae61b6bb1cec81a00ce65a784c4aa7fe79935ec1fadee65e7a0238186fffd3848275dc275b26ccf1'],
  ['eip1559BigValue', '02f84c0109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535a0800000000000000000000000000000000000000000000000000000000000000784deadbeefc0',
    '02f88f0109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535a0800000000000000000000000000000000000000000000000000000000000000784deadbeefc001a065a773b455bc59ec927a7c471daa4e3245272efe116ef9986ac75917c7cf5b06a023cc77354f88d45bfda4fc29182681c9748ef4660829fc69685ce40e86e73c66'],
];

const MALFORMED_TRANSACTIONS = [
  ['legacy chainId 2^64+1 (truncated: chain 1)', 'f5098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080890100000000000000018080'],
  ['legacy chainId 2^64+137 (truncated: Polygon)', 'f5098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080890100000000000000898080'],
  ['legacy nonce 0x010000000000000009', 'f5890100000000000000098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy nonce with a leading zero', 'ee8200098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy gasPrice 9 bytes', 'f009890100000004a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy gasLimit 9 bytes', 'f3098504a817c80089010000000000005208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy chainId above EIP-2294', 'f4098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080887fffffffffffffdc8080'],
  ['EIP-1559 chainId 2^64+1', '02f83c8901000000000000000109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0808080'],
  ['EIP-1559 maxFeePerGas 9 bytes', '02f70109843b9aca00890100000006fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0808080'],
  ['EIP-1559 value 33 bytes', '02f84c0109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535a101000000000000000000000000000000000000000000000000000000000000000080c0808080'],
  ['EIP-1559 chainId with a leading zero', '02f582000109843b9aca008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0808080'],
  ['EIP-2930 chainId 2^64+1', '01f789010000000000000001098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c0808080'],
  ['legacy nonce as a one-byte string', 'ed81098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy list in long form', 'f82c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'],
  ['legacy trailing byte', 'ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008001808000'],
  ['legacy tenth field', 'ed098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008001808080'],
];

test('Ethereum tx: parse then sign matches ethers for legacy, EIP-2930 and EIP-1559', () => {
  const problems = [];
  for (const [name, unsignedHex, signedHex] of ETHERS_VECTORS) {
    let tx = null;
    try {
      tx = wallet.ethereum.tx.parse(hexToBytes(unsignedHex));
      const signed = bytesToHex(tx.sign(hexToBytes('46'.repeat(32))).serialize());
      if (signed !== signedHex) problems.push(`${name}: signed ${signed}`);
    } catch (error) {
      problems.push(`${name}: ${error.message}`);
    } finally {
      tx?.destroy();
    }
    const parsed = wallet.ethereum.tx.parse(hexToBytes(signedHex));
    try {
      if (bytesToHex(parsed.serialize()) !== signedHex) problems.push(`${name}: signed bytes do not round-trip`);
    } finally {
      parsed.destroy();
    }
  }
  assertEqual(problems.join('\n'), '', 'every ethers vector');
});

test('Ethereum tx: parse refuses truncated, over-long and non-canonical fields', () => {
  const parsedAnyway = [];
  for (const [name, hex] of MALFORMED_TRANSACTIONS) {
    let tx = null;
    try {
      tx = wallet.ethereum.tx.parse(hexToBytes(hex));
      parsedAnyway.push(name);
    } catch {
      // refused
    } finally {
      tx?.destroy();
    }
  }
  assertEqual(parsedAnyway.join(', '), '', 'malformed transactions must not parse');
});
