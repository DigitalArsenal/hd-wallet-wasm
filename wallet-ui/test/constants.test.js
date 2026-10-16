import { describe, it, expect } from 'vitest';
import {
  cryptoConfig,
  coinTypeToConfig,
  buildSigningPath,
  buildEncryptionPath,
} from '../src/constants.js';
import * as constants from '../src/constants.js';

describe('cryptoConfig', () => {
  it('has all expected networks', () => {
    // The demo UI currently enables BTC/ETH/SOL only. (Other configs are kept commented out.)
    const expected = ['btc', 'eth', 'sol'];
    for (const key of expected) {
      expect(cryptoConfig).toHaveProperty(key);
    }
  });

  it('each config has required fields', () => {
    for (const [key, config] of Object.entries(cryptoConfig)) {
      expect(config).toHaveProperty('name');
      expect(config).toHaveProperty('symbol');
      expect(config).toHaveProperty('coinType');
      expect(config).toHaveProperty('explorer');
      expect(typeof config.name).toBe('string');
      expect(typeof config.symbol).toBe('string');
      expect(typeof config.coinType).toBe('number');
      expect(typeof config.explorer).toBe('string');
      expect(config.explorer).toMatch(/^https:\/\//);
    }
  });

  it('formatBalance functions work', () => {
    expect(cryptoConfig.btc.formatBalance(100000000)).toBe('1.00000000 BTC');
    expect(cryptoConfig.eth.formatBalance(1e18)).toBe('1.000000 ETH');
    expect(cryptoConfig.sol.formatBalance(1e9)).toBe('1.0000 SOL');
  });
});

describe('coinTypeToConfig', () => {
  it('maps coin type numbers to configs', () => {
    expect(coinTypeToConfig[0].symbol).toBe('BTC');
    expect(coinTypeToConfig[60].symbol).toBe('ETH');
    expect(coinTypeToConfig[501].symbol).toBe('SOL');
  });

  it('includes key field with original key name', () => {
    expect(coinTypeToConfig[0].key).toBe('btc');
    expect(coinTypeToConfig[60].key).toBe('eth');
  });

  it('returns undefined for unknown coin type', () => {
    expect(coinTypeToConfig[99999]).toBeUndefined();
  });
});

describe('buildSigningPath', () => {
  it('builds standard BIP44 signing path', () => {
    expect(buildSigningPath(0, 0, 0)).toBe("m/44'/0'/0'/0/0");
  });

  it('builds Ethereum path', () => {
    expect(buildSigningPath(60, 0, 0)).toBe("m/44'/60'/0'/0/0");
  });

  it('supports custom account and index', () => {
    expect(buildSigningPath(0, 2, 5)).toBe("m/44'/0'/2'/0/5");
  });

  it('defaults account and index to 0', () => {
    expect(buildSigningPath(501)).toBe("m/44'/501'/0'/0/0");
  });
});

describe('buildEncryptionPath', () => {
  it('uses change=1 for encryption keys', () => {
    expect(buildEncryptionPath(0, 0, 0)).toBe("m/44'/0'/0'/1/0");
  });

  it('builds correct Ethereum encryption path', () => {
    expect(buildEncryptionPath(60, 0, 0)).toBe("m/44'/60'/0'/1/0");
  });
});

describe('Storage constants', () => {
  it('the 2.x PKI demo key name is gone', () => {
    expect(constants).not.toHaveProperty('PKI_STORAGE_KEY');
  });
});
