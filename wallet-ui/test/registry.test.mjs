import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, test } from 'vitest';

import {
  resolveRegistryBinding,
  verifyRegistry,
} from '../origin-app/registry.mjs';

const PUBLIC_OPERATIONS = [
  'sdn.wallet.account.v1',
  'sdn.wallet.connect.v1',
];
const SDN_OPERATIONS = [
  'sdn.auth.jcs-envelope.v2',
  'sdn.auth.raw-challenge.v1',
  ...PUBLIC_OPERATIONS,
];
const REVIEW_OPERATIONS = [
  'sdn.asset-review.authority-activation.v1',
  'sdn.asset-review.decision.v1',
  ...PUBLIC_OPERATIONS,
];
const SDN_AUDIENCES = ['sdn-login:sdn.spaceaware.io'];
const REVIEW_AUDIENCES = [
  'asset-review-authority:assets.ipfs.01',
  'asset-review:assets.ipfs.01',
];

const EXPECTED_CLIENTS = [
  ['sdn-landing-web-v1', 'https://spacedatanetwork.org', 'https://spacedatanetwork.org/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-standards-web-v1', 'https://spacedatastandards.org', 'https://spacedatastandards.org/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-flatbuffers-pages-v1', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/flatbuffers/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-flatsql-pages-v1', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/flatsql/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-module-sdk-pages-v1', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/space-data-module-sdk/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['spaceaware-web-v1', 'https://spaceaware.io', 'https://spaceaware.io/wallet/callback', PUBLIC_OPERATIONS, []],
  ['sdn-node-console-v1', 'https://sdn.spaceaware.io', 'https://sdn.spaceaware.io/wallet/callback', SDN_OPERATIONS, SDN_AUDIENCES],
  ['orbpro-pages-v1', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/OrbPro/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-asset-models-pages-v1', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/asset-models/wallet-callback.html', PUBLIC_OPERATIONS, []],
  ['sdn-asset-review-v1', 'https://review.spacedatanetwork.org', 'https://review.spacedatanetwork.org/wallet/callback', REVIEW_OPERATIONS, REVIEW_AUDIENCES],
];

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite registry number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function expectDeepFrozen(value) {
  expect(Object.isFrozen(value)).toBe(true);
  if (!value || typeof value !== 'object') return;
  for (const item of Object.values(value)) expectDeepFrozen(item);
}

describe('committed wallet client registry', () => {
  test('has a self-authenticating JCS release digest', async () => {
    const bytes = await readFile(new URL('../relay/config/client-registry.v1.json', import.meta.url), 'utf8');
    const source = JSON.parse(bytes);
    const { registryReleaseSha256, ...unsigned } = source;
    const digest = createHash('sha256').update(jcs(unsigned), 'utf8').digest('hex');
    expect(registryReleaseSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(digest).toBe(registryReleaseSha256);
    expect(bytes).toBe(`${jcs(source)}\n`);
  });

  test('contains exactly the ten reviewed HTTPS client rows and allowlists', () => {
    const registry = verifyRegistry();
    expect(registry.schemaVersion).toBe(1);
    expect(registry.clients).toHaveLength(EXPECTED_CLIENTS.length);
    expect(registry.clients.map(({
      clientId,
      requestOrigin,
      callbackUri,
      allowedOperations,
      audiences,
      operationBindings,
    }) => [
      clientId,
      requestOrigin,
      callbackUri,
      allowedOperations,
      audiences,
    ])).toEqual(EXPECTED_CLIENTS);
    for (const client of registry.clients) {
      expect(client.operationBindings.map(({ operation }) => operation)).toEqual(client.allowedOperations);
      expect([...new Set(client.operationBindings
        .map(({ audience }) => audience)
        .filter((audience) => audience !== null))].sort()).toEqual(client.audiences);
    }
    expectDeepFrozen(registry);
  });

  test('resolves only exact clientId + requestOrigin + operation triples', () => {
    const binding = resolveRegistryBinding({
      clientId: 'sdn-node-console-v1',
      requestOrigin: 'https://sdn.spaceaware.io',
      operation: 'sdn.auth.jcs-envelope.v2',
    });
    expect(binding).toEqual({
      audience: 'sdn-login:sdn.spaceaware.io',
      callbackUri: 'https://sdn.spaceaware.io/wallet/callback',
      clientDisplayName: 'SDN Node Console',
      clientId: 'sdn-node-console-v1',
      maxLifetimeSeconds: 300,
      operation: 'sdn.auth.jcs-envelope.v2',
      requestOrigin: 'https://sdn.spaceaware.io',
      registryReleaseSha256: expect.stringMatching(/^[0-9a-f]{64}$/u),
      registryRow: 'sdn-node-console-v2',
      serviceActivationState: null,
      serviceInstance: null,
    });
    expectDeepFrozen(binding);

    for (const input of [
      { clientId: 'sdn-node-console-v1', requestOrigin: 'http://sdn.spaceaware.io', operation: 'sdn.auth.jcs-envelope.v2' },
      { clientId: 'sdn-node-console-v1', requestOrigin: 'https://SDN.spaceaware.io', operation: 'sdn.auth.jcs-envelope.v2' },
      { clientId: 'sdn-landing-web-v1', requestOrigin: 'https://spacedatanetwork.org', operation: 'sdn.auth.raw-challenge.v1' },
      { clientId: 'sdn-desktop-v1', requestOrigin: 'https://sdn.spaceaware.io', operation: 'sdn.wallet.connect.v1' },
    ]) {
      expect(() => resolveRegistryBinding(input)).toThrow();
    }
  });

  test.each(['callbackUri', 'audience', 'maxLifetimeSeconds', 'origin', 'originOverride'])(
    'rejects caller %s overrides',
    (field) => {
      expect(() => resolveRegistryBinding({
        clientId: 'sdn-node-console-v1',
        requestOrigin: 'https://sdn.spaceaware.io',
        operation: 'sdn.auth.jcs-envelope.v2',
        [field]: field === 'maxLifetimeSeconds' ? 999 : 'https://attacker.invalid',
      })).toThrow(/field/iu);
    },
  );

  test('rejects hidden, accessor, and symbol override fields', () => {
    const base = {
      clientId: 'sdn-node-console-v1',
      requestOrigin: 'https://sdn.spaceaware.io',
      operation: 'sdn.auth.jcs-envelope.v2',
    };
    const hidden = { ...base };
    Object.defineProperty(hidden, 'callbackUri', {
      enumerable: false,
      value: 'https://attacker.invalid',
    });
    const accessor = { ...base };
    Object.defineProperty(accessor, 'audience', {
      enumerable: false,
      get: () => 'attacker',
    });
    const symbol = { ...base, [Symbol('callbackUri')]: 'https://attacker.invalid' };
    expect(() => resolveRegistryBinding(hidden)).toThrow(/field/iu);
    expect(() => resolveRegistryBinding(accessor)).toThrow(/field/iu);
    expect(() => resolveRegistryBinding(symbol)).toThrow(/field/iu);
  });

  test('projects the three canonical signing rows exactly onto the compiled native registry', () => {
    const expected = [
      {
        clientId: 'sdn-node-console-v1',
        requestOrigin: 'https://sdn.spaceaware.io',
        operation: 'sdn.auth.jcs-envelope.v2',
        audience: 'sdn-login:sdn.spaceaware.io',
        registryRow: 'sdn-node-console-v2',
        serviceInstance: null,
        serviceActivationState: null,
      },
      {
        clientId: 'sdn-asset-review-v1',
        requestOrigin: 'https://review.spacedatanetwork.org',
        operation: 'sdn.asset-review.authority-activation.v1',
        audience: 'asset-review-authority:assets.ipfs.01',
        registryRow: 'asset-review-authority-activation-v1',
        serviceInstance: 'assets.ipfs.01/asset-review-attestation',
        serviceActivationState: 'unactivated',
      },
      {
        clientId: 'sdn-asset-review-v1',
        requestOrigin: 'https://review.spacedatanetwork.org',
        operation: 'sdn.asset-review.decision.v1',
        audience: 'asset-review:assets.ipfs.01',
        registryRow: 'asset-review-decision-v1',
        serviceInstance: null,
        serviceActivationState: 'activated',
      },
    ];

    const actual = expected.map(({ clientId, requestOrigin, operation }) => {
      const binding = resolveRegistryBinding({ clientId, requestOrigin, operation });
      return {
        clientId: binding.clientId,
        requestOrigin: binding.requestOrigin,
        operation: binding.operation,
        audience: binding.audience,
        registryRow: binding.registryRow,
        serviceInstance: binding.serviceInstance,
        serviceActivationState: binding.serviceActivationState,
      };
    });
    expect(actual).toEqual(expected);
    expect(actual.every((_row, index) => resolveRegistryBinding({
      clientId: expected[index].clientId,
      requestOrigin: expected[index].requestOrigin,
      operation: expected[index].operation,
    }).maxLifetimeSeconds === 300)).toBe(true);
  });

  test('contains no generic, desktop, node-identity, EPM, loopback, HTTP, wildcard, or custom-scheme row', () => {
    const registryText = JSON.stringify(verifyRegistry());
    for (const forbidden of [
      /generic-sign/iu,
      /node-identity/iu,
      /epm/iu,
      /desktop/iu,
      /localhost/iu,
      /127\.0\.0\.1/iu,
      /http:\/\//iu,
      /\*/u,
      /(?:^|["'])(?!https:\/\/)[a-z][a-z0-9+.-]*:\/\//iu,
    ]) {
      expect(registryText).not.toMatch(forbidden);
    }
  });

  test('returns defensive immutable copies rather than writable registry state', () => {
    const first = resolveRegistryBinding({
      clientId: 'sdn-asset-review-v1',
      requestOrigin: 'https://review.spacedatanetwork.org',
      operation: 'sdn.asset-review.decision.v1',
    });
    expect(() => { first.audience = 'changed'; }).toThrow();
    const second = resolveRegistryBinding({
      clientId: 'sdn-asset-review-v1',
      requestOrigin: 'https://review.spacedatanetwork.org',
      operation: 'sdn.asset-review.decision.v1',
    });
    expect(second).not.toBe(first);
    expect(second.audience).toBe('asset-review:assets.ipfs.01');
  });
});
