// SEC-014 / SEC-057: what the Send form accepts, and how the wallet reads
// back what it is about to sign. A recipient that does not parse exactly is
// refused (the 2.1.0 builder signed it as a transfer to 0x00…00), the zero
// address is refused, mixed case must pass EIP-55, amounts are exact
// decimals in integer base units, and Bitcoin input values come from the
// previous transaction's bytes, never from an API.

import { describe, expect, it } from 'vitest';

import {
  BTC_MAX_SATS,
  ETH_ZERO_ADDRESS,
  UINT256_MAX,
  btcScriptToAddress,
  bytesToHex,
  decodeEip1559,
  encodeUnsignedEip1559,
  formatUnits,
  hexToBytes,
  parseBtcRecipient,
  parseBtcTransaction,
  parseDecimalAmount,
  parseEthRecipient,
  toChecksumAddress,
  verifyUtxo,
} from '../src/send-safety.js';
import { btcAddressToScriptPubKey } from '../src/blockchain-trust.js';
import { rawTx } from './helpers/btc-raw.mjs';

const GOOD = '0x52908400098527886E0F7030069857D2E4169EE7';

function code(fn) {
  try {
    fn();
  } catch (error) {
    return error.code ?? error.message;
  }
  return 'ACCEPTED';
}

describe('Ethereum recipient', () => {
  it('accepts exactly 0x + 40 hex digits and returns the EIP-55 form', () => {
    expect(parseEthRecipient(GOOD)).toEqual({ address: GOOD, lower: GOOD.toLowerCase() });
    expect(parseEthRecipient(GOOD.toLowerCase()).address).toBe(GOOD);
    expect(parseEthRecipient(`0x${GOOD.slice(2).toUpperCase()}`).address).toBe(GOOD);
    // Whitespace around a paste is not part of the address.
    expect(parseEthRecipient(`  ${GOOD}\n`).address).toBe(GOOD);
  });

  it('matches the EIP-55 specification vectors', () => {
    for (const address of [
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
      '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
      '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    ]) {
      expect(toChecksumAddress(address.toLowerCase())).toBe(address);
      expect(parseEthRecipient(address).address).toBe(address);
    }
  });

  it('refuses a mixed-case address whose EIP-55 checksum fails', () => {
    // One letter's case flipped.
    expect(code(() => parseEthRecipient('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'))).toBe('BAD_CHECKSUM');
    expect(code(() => parseEthRecipient('0x52908400098527886e0F7030069857D2E4169EE7'))).toBe('BAD_CHECKSUM');
  });

  it('refuses the zero (burn) address however it is typed', () => {
    expect(code(() => parseEthRecipient(ETH_ZERO_ADDRESS))).toBe('ZERO_ADDRESS');
    expect(code(() => parseEthRecipient(`0x${'0'.repeat(40)}`.toUpperCase().replace('0X', '0x')))).toBe('ZERO_ADDRESS');
  });

  it('refuses every input that the 2.1.0 builder silently signed to 0x00…00', () => {
    for (const bad of [
      'vitalik.eth',
      GOOD.slice(0, -1), // 39 hex digits
      `${GOOD}7`, // 41
      `${GOOD}x`, // extra character
      `0x0x${GOOD.slice(4)}`, // double prefix (the 6e3a7ba bypass)
      `0X0x${GOOD.slice(4)}`,
      `0X${GOOD.slice(2)}`, // capital X prefix
      GOOD.slice(2), // no prefix
      `${GOOD}\u0000garbage`, // NUL suffix
      `0x５${GOOD.slice(3)}`, // fullwidth digit
      'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
      '',
      '   ',
    ]) {
      expect([bad, code(() => parseEthRecipient(bad))]).not.toEqual([bad, 'ACCEPTED']);
    }
    expect(code(() => parseEthRecipient(null))).toBe('EMPTY');
    expect(code(() => parseEthRecipient(undefined))).toBe('EMPTY');
  });
});

describe('amounts', () => {
  it('parses decimal strings into exact integer base units', () => {
    expect(parseDecimalAmount('20', 18)).toBe(20n * 10n ** 18n);
    expect(parseDecimalAmount('20.000000000000000001', 18)).toBe(20n * 10n ** 18n + 1n);
    expect(parseDecimalAmount('0.000000000000000001', 18)).toBe(1n);
    expect(parseDecimalAmount('.5', 8)).toBe(50_000_000n);
    expect(parseDecimalAmount('123456789.12345678', 8)).toBe(12_345_678_912_345_678n);
    // 2^64 wei and more is exact (2.1.0 wrapped it modulo 2^64).
    expect(parseDecimalAmount('18446744073709551616', 0)).toBe(1n << 64n);
    expect(parseDecimalAmount(UINT256_MAX.toString(), 0, { max: UINT256_MAX })).toBe(UINT256_MAX);
  });

  it('refuses anything but a plain positive decimal, and never rounds', () => {
    expect(code(() => parseDecimalAmount('0.0000000000000000001', 18))).toBe('TOO_PRECISE');
    expect(code(() => parseDecimalAmount('0.123456789', 8))).toBe('TOO_PRECISE');
    for (const bad of ['1e18', '-1', '+1', '1,5', '0x10', 'Infinity', 'NaN', '1.', '1..2', '١', '']) {
      expect([bad, code(() => parseDecimalAmount(bad, 18))]).toEqual([bad, 'INVALID_AMOUNT']);
    }
    expect(code(() => parseDecimalAmount('0', 18))).toBe('ZERO_AMOUNT');
    expect(code(() => parseDecimalAmount('0.000', 18))).toBe('ZERO_AMOUNT');
    expect(code(() => parseDecimalAmount((UINT256_MAX + 1n).toString(), 0, { max: UINT256_MAX }))).toBe('AMOUNT_TOO_LARGE');
    expect(code(() => parseDecimalAmount('21000001', 8, { max: BTC_MAX_SATS }))).toBe('AMOUNT_TOO_LARGE');
  });

  it('formats base units exactly', () => {
    expect(formatUnits(20n * 10n ** 18n, 18)).toBe('20');
    expect(formatUnits(1n, 18)).toBe('0.000000000000000001');
    expect(formatUnits(1n << 64n, 18)).toBe('18.446744073709551616');
    expect(formatUnits(150_000_000n, 8)).toBe('1.5');
  });
});

describe('EIP-1559 decoding', () => {
  // Built by hd-wallet-wasm (createEIP1559, nonce 3, fees 2/100, gas 21000,
  // to GOOD, value 0.5 ETH), unsigned and signed with the scalar 7.
  const unsigned = hexToBytes('02ea010302648252089452908400098527886e0f7030069857d2e4169ee78806f05b59d3b2000080c0808080');
  const signed = hexToBytes('02f86a010302648252089452908400098527886e0f7030069857d2e4169ee78806f05b59d3b2000080c001a024dee6ec42ce32d34dc48fbdecbe8742f574b17f1de7ab668880799df58fb667a07604abf21a3c2d942882bbaeb7e2c621ba21638621be71d03ebf35657398ac45');

  it('reads the recipient and value back from the bytes', () => {
    const u = decodeEip1559(unsigned);
    // The builder writes empty v/r/s placeholders when unsigned: 12 fields,
    // read as unsigned.
    expect(u.signed).toBe(false);
    expect(u.to).toBe(GOOD.toLowerCase());
    expect(u.value).toBe(5n * 10n ** 17n);
    expect(u.chainId).toBe(1n);
    expect(u.nonce).toBe(3n);
    expect(u.gasLimit).toBe(21000n);
    const s = decodeEip1559(signed);
    expect(s.signed).toBe(true);
    expect(s.yParity).toBe(1n);
    expect(s.r > 0n && s.s > 0n).toBe(true);
  });

  it('refuses malformed or non-canonical encodings', () => {
    expect(code(() => decodeEip1559(signed.slice(0, -1)))).toBe('BAD_TX');
    expect(code(() => decodeEip1559(Uint8Array.from([...signed, 0])))).toBe('BAD_TX');
    expect(code(() => decodeEip1559(Uint8Array.from([0x01, ...signed.slice(1)])))).toBe('BAD_TX');
    // A 19-byte recipient field.
    const short = Uint8Array.from(unsigned);
    short[9] = 0x93;
    expect(code(() => decodeEip1559(short))).toBe('BAD_TX');
  });
});

describe('EIP-1559 encoding (the 256-bit value path)', () => {
  const fields = {
    chainId: 1n, nonce: 3n, maxPriorityFeePerGas: 2n, maxFeePerGas: 100n, gasLimit: 21000n,
    to: GOOD.toLowerCase(), value: 5n * 10n ** 17n,
  };

  it('writes exactly the bytes hd-wallet-wasm serializes for an unsigned transaction', () => {
    expect(bytesToHex(encodeUnsignedEip1559(fields)))
      .toBe('02ea010302648252089452908400098527886e0f7030069857d2e4169ee78806f05b59d3b2000080c0808080');
  });

  it('carries the whole 256-bit value, and every field round-trips', () => {
    for (const value of [0n, 1n, (1n << 64n) - 1n, 1n << 64n, 20n * 10n ** 18n, UINT256_MAX]) {
      const data = Uint8Array.from({ length: 80 }, (_, i) => i);
      const decoded = decodeEip1559(encodeUnsignedEip1559({ ...fields, value, data }));
      expect(decoded.value).toBe(value);
      expect(decoded.to).toBe(GOOD.toLowerCase());
      expect(decoded.signed).toBe(false);
      expect(bytesToHex(decoded.data)).toBe(bytesToHex(data));
      expect(decoded.gasLimit).toBe(21000n);
    }
  });

  it('refuses what the builder would truncate or misread', () => {
    expect(code(() => encodeUnsignedEip1559({ ...fields, value: UINT256_MAX + 1n }))).toBe('BAD_TX');
    expect(code(() => encodeUnsignedEip1559({ ...fields, value: -1n }))).toBe('BAD_TX');
    expect(code(() => encodeUnsignedEip1559({ ...fields, value: 5 }))).toBe('BAD_TX');
    for (const key of ['chainId', 'nonce', 'maxPriorityFeePerGas', 'maxFeePerGas', 'gasLimit']) {
      expect(code(() => encodeUnsignedEip1559({ ...fields, [key]: 1n << 64n }))).toBe('BAD_TX');
    }
    for (const to of [undefined, '', GOOD, GOOD.toLowerCase().slice(0, -1), `${GOOD.toLowerCase()}0`, 'vitalik.eth']) {
      expect(code(() => encodeUnsignedEip1559({ ...fields, to }))).toBe('BAD_TX');
    }
    expect(code(() => encodeUnsignedEip1559({ ...fields, to: ETH_ZERO_ADDRESS }))).toBe('ZERO_ADDRESS');
    expect(code(() => encodeUnsignedEip1559({ ...fields, data: 'ab' }))).toBe('BAD_TX');
  });
});

describe('Bitcoin recipient', () => {
  it('maps every supported address type to its own script', () => {
    // Vectors: BIP-173 / BIP-350 and well-known mainnet addresses.
    expect(bytesToHex(parseBtcRecipient('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2').script)).toBe('76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac');
    expect(bytesToHex(parseBtcRecipient('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy').script)).toBe('a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87');
    expect(bytesToHex(parseBtcRecipient('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').script)).toBe('0014751e76e8199196d454941c45d1b3a323f1433bd6');
    expect(bytesToHex(parseBtcRecipient('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').script)).toBe('0014751e76e8199196d454941c45d1b3a323f1433bd6');
    expect(parseBtcRecipient('bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3').type).toBe('p2wsh');
    expect(parseBtcRecipient('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0').type).toBe('p2tr');
    for (const address of [
      '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
      '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
      'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
    ]) {
      expect(btcScriptToAddress(parseBtcRecipient(address).script)).toBe(address);
    }
  });

  it('pays a P2SH address with a P2SH script (the old change helper wrote P2PKH)', () => {
    // On origin/main btcAddressToScriptPubKey('3…') returned 76a914<hash>88ac,
    // an output nobody can spend.
    expect(btcAddressToScriptPubKey('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).toBe('a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87');
  });

  it('refuses bad checksums, mixed case, testnet, v0 with bech32m and v1 with bech32', () => {
    for (const bad of [
      '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3',
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
      'bc1qw508d6qejxtdg4y5r3zArvary0c5xw7kv8f3t4',
      'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
      'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn',
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh', // v0 program, bech32m checksum
      'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', // v1 program, bech32 checksum
      GOOD,
      '',
    ]) {
      expect([bad, code(() => parseBtcRecipient(bad))]).not.toEqual([bad, 'ACCEPTED']);
    }
  });
});

describe('verified UTXOs', () => {
  const mine = parseBtcRecipient('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2').script;
  const other = parseBtcRecipient('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy').script;

  it('takes the value from the raw transaction, whatever the API said', () => {
    for (const witness of [false, true]) {
      const { hex, txid } = rawTx({ witness, outputs: [{ value: 7_000n, script: other }, { value: 1_000_000n, script: mine }] });
      expect(parseBtcTransaction(hexToBytes(hex)).txid).toBe(txid);
      const utxo = verifyUtxo({ txid, vout: 1, value: 500_000_000 }, hex, mine);
      expect(utxo.value).toBe(1_000_000n);
      expect(utxo.scriptpubkey).toBe(bytesToHex(mine));
    }
  });

  it('refuses a transaction that does not hash to the txid, a missing output, or someone else’s output', () => {
    const { hex, txid } = rawTx({ outputs: [{ value: 7_000n, script: other }, { value: 1_000_000n, script: mine }] });
    const tampered = `${hex.slice(0, -20)}${'ff'.repeat(2)}${hex.slice(-16)}`;
    expect(code(() => verifyUtxo({ txid, vout: 1 }, tampered, mine))).toBe('BAD_UTXO');
    expect(code(() => verifyUtxo({ txid, vout: 5 }, hex, mine))).toBe('BAD_UTXO');
    expect(code(() => verifyUtxo({ txid, vout: 0 }, hex, mine))).toBe('BAD_UTXO');
    expect(code(() => verifyUtxo({ txid: 'zz', vout: 0 }, hex, mine))).toBe('BAD_UTXO');
    expect(code(() => verifyUtxo({ txid, vout: 1 }, `${hex}00`, mine))).toBe('BAD_TX');
  });
});
