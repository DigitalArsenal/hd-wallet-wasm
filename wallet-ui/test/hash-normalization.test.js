import { describe, it, expect } from 'vitest';
import { normalizeTabHash } from '../src/hash.js';

describe('normalizeTabHash', () => {
  it('normalizes leading slash hashes to tab ids', () => {
    expect(normalizeTabHash('/peers')).toBe('peers');
    expect(normalizeTabHash('/peers?tab=1')).toBe('peers');
    expect(normalizeTabHash('/peers#section')).toBe('peers');
    expect(normalizeTabHash('peers')).toBe('peers');
  });

  it('strips trailing "-tab" and normalizes case', () => {
    expect(normalizeTabHash('PEERS-TAB')).toBe('peers');
    expect(normalizeTabHash('/peers-tab')).toBe('peers');
    expect(normalizeTabHash('/peers-tab?foo=bar')).toBe('peers');
  });

  it('removes unsafe selector characters', () => {
    expect(normalizeTabHash('/peers view')).toBe('peersview');
    expect(normalizeTabHash('/peers[0]')).toBe('peers0');
    expect(normalizeTabHash('/peers!')).toBe('peers');
  });

  it('keeps empty values empty', () => {
    expect(normalizeTabHash('')).toBe('');
    expect(normalizeTabHash('#/peers')).toBe('peers');
    expect(normalizeTabHash(undefined)).toBe('');
  });

  it('returns values safe for selector interpolation', () => {
    const candidates = [
      '/peers',
      '/peers?x=1',
      '/peers#x',
      '/peers-tab',
      'peers-tab',
      'PEERS',
      '/trusted_nodes',
      '/trusted-nodes',
      '/peers view',
      '',
    ];

    for (const candidate of candidates) {
      const normalized = normalizeTabHash(candidate);

      if (!normalized) {
        continue;
      }

      expect(normalized).toMatch(/^[a-z0-9_-]+$/);
      const selector = `#${normalized}-tab`;
      expect(selector).toBe(`#${normalized}-tab`);
    }
  });
});
