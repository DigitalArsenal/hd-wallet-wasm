import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { exactObject, isLowerHex64, jcs, parseStrictJson, relayError, ERRORS, sha256Hex } from './json.js';

export interface RegistryBinding {
  readonly callbackUri: string;
  readonly clientDisplayName: string;
  readonly clientId: string;
  readonly maxLifetimeSeconds: number;
  readonly operation: string;
  readonly requestOrigin: string;
  readonly registryReleaseSha256: string;
}

interface RegistryClient {
  readonly allowedOperations: readonly string[];
  readonly callbackUri: string;
  readonly clientDisplayName: string;
  readonly clientId: string;
  readonly requestOrigin: string;
}

const REGISTRY_FIELDS = ['clients', 'registryReleaseSha256', 'schemaVersion'] as const;
const CLIENT_FIELDS = [
  'allowedOperations',
  'audiences',
  'callbackUri',
  'clientDisplayName',
  'clientId',
  'operationBindings',
  'requestOrigin',
] as const;
const BINDING_FIELDS = [
  'audience',
  'maxLifetimeSeconds',
  'operation',
  'registryRow',
  'serviceActivationState',
  'serviceInstance',
] as const;
const EXPECTED_RELEASE_SHA256 = 'e1ce6fe903c9700484a8a87d96581c8cad97063dabf63030b4518a31a3bdaa93';
const OPERATION_POLICY: Readonly<Record<string, Readonly<{
  audience: string | null;
  registryRow: string | null;
  serviceActivationState: string | null;
  serviceInstance: string | null;
}>>> = Object.freeze({
  'sdn.asset-review.authority-activation.v1': Object.freeze({
    audience: 'asset-review-authority:assets.ipfs.01',
    registryRow: 'asset-review-authority-activation-v1',
    serviceActivationState: 'unactivated',
    serviceInstance: 'assets.ipfs.01/asset-review-attestation',
  }),
  'sdn.asset-review.decision.v1': Object.freeze({
    audience: 'asset-review:assets.ipfs.01',
    registryRow: 'asset-review-decision-v1',
    serviceActivationState: 'activated',
    serviceInstance: null,
  }),
  'sdn.auth.jcs-envelope.v2': Object.freeze({
    audience: 'sdn-login:sdn.spaceaware.io',
    registryRow: 'sdn-node-console-v2',
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.auth.raw-challenge.v1': Object.freeze({
    audience: 'sdn-login:sdn.spaceaware.io',
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.wallet.account.v1': Object.freeze({
    audience: null,
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.wallet.connect.v1': Object.freeze({
    audience: null,
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
});

function validHttpsOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.includes('*')) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port
      && url.pathname === '/' && !url.search && !url.hash && url.origin === value;
  } catch {
    return false;
  }
}

function validHttpsCallback(value: unknown, requestOrigin: string): value is string {
  if (typeof value !== 'string' || value.includes('*')) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port
      && !url.search && !url.hash && url.origin === requestOrigin && url.href === value;
  } catch {
    return false;
  }
}

export class ClientRegistry {
  readonly releaseSha256: string;
  readonly clients: readonly RegistryClient[];

  constructor(registryPath = fileURLToPath(new URL('../../config/client-registry.v1.json', import.meta.url))) {
    let parsed: unknown;
    try {
      parsed = parseStrictJson(readFileSync(registryPath, 'utf8'));
    } catch {
      throw new Error('wallet relay registry is invalid');
    }
    const source = exactObject(parsed, REGISTRY_FIELDS);
    if (source.schemaVersion !== 1 || !isLowerHex64(source.registryReleaseSha256)
        || source.registryReleaseSha256 !== EXPECTED_RELEASE_SHA256) {
      throw new Error('wallet relay registry is invalid');
    }
    const unsigned = {
      clients: source.clients,
      schemaVersion: source.schemaVersion,
    };
    if (sha256Hex(jcs(unsigned)) !== source.registryReleaseSha256) {
      throw new Error('wallet relay registry release digest mismatch');
    }
    if (!Array.isArray(source.clients) || source.clients.length === 0 || source.clients.length > 64) {
      throw new Error('wallet relay registry is invalid');
    }

    const seenClients = new Set<string>();
    const clients: RegistryClient[] = [];
    for (const rawClient of source.clients) {
      const client = exactObject(rawClient, CLIENT_FIELDS);
      if (typeof client.clientId !== 'string'
          || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(client.clientId)
          || seenClients.has(client.clientId)
          || typeof client.clientDisplayName !== 'string'
          || client.clientDisplayName.length < 1
          || client.clientDisplayName.length > 80
          || !validHttpsOrigin(client.requestOrigin)
          || !validHttpsCallback(client.callbackUri, client.requestOrigin)) {
        throw new Error('wallet relay registry is invalid');
      }
      if (!Array.isArray(client.allowedOperations) || !Array.isArray(client.operationBindings)
          || !Array.isArray(client.audiences)
          || client.allowedOperations.length !== client.operationBindings.length
          || client.allowedOperations.length === 0 || client.allowedOperations.length > 16) {
        throw new Error('wallet relay registry is invalid');
      }
      const operations: string[] = [];
      for (let index = 0; index < client.operationBindings.length; index += 1) {
        const operation = exactObject(client.operationBindings[index], BINDING_FIELDS);
        const operationId = typeof operation.operation === 'string' ? operation.operation : null;
        const policy = operationId
          ? OPERATION_POLICY[operationId]
          : undefined;
        if (!operationId || !policy
            || operationId !== client.allowedOperations[index]
            || operation.maxLifetimeSeconds !== 300
            || operation.audience !== policy.audience
            || operation.registryRow !== policy.registryRow
            || operation.serviceActivationState !== policy.serviceActivationState
            || operation.serviceInstance !== policy.serviceInstance
            || operations.includes(operationId)) {
          throw new Error('wallet relay registry is invalid');
        }
        operations.push(operationId);
      }
      const expectedAudiences = [...new Set(client.operationBindings
        .map((value) => exactObject(value, BINDING_FIELDS).audience)
        .filter((value): value is string => typeof value === 'string'))].sort();
      if (jcs(client.audiences) !== jcs(expectedAudiences)) {
        throw new Error('wallet relay registry is invalid');
      }
      seenClients.add(client.clientId);
      clients.push(Object.freeze({
        allowedOperations: Object.freeze([...operations]),
        callbackUri: client.callbackUri,
        clientDisplayName: client.clientDisplayName,
        clientId: client.clientId,
        requestOrigin: client.requestOrigin,
      }));
    }
    this.releaseSha256 = source.registryReleaseSha256;
    this.clients = Object.freeze(clients);
  }

  hasOrigin(origin: unknown): origin is string {
    return typeof origin === 'string' && this.clients.some((client) => client.requestOrigin === origin);
  }

  resolve(clientId: unknown, requestOrigin: unknown, operation: unknown): RegistryBinding {
    if (typeof clientId !== 'string' || typeof requestOrigin !== 'string' || typeof operation !== 'string') {
      throw relayError(ERRORS.unregistered);
    }
    const client = this.clients.find((candidate) => candidate.clientId === clientId
      && candidate.requestOrigin === requestOrigin
      && candidate.allowedOperations.includes(operation));
    if (!client) throw relayError(ERRORS.unregistered);
    return Object.freeze({
      callbackUri: client.callbackUri,
      clientDisplayName: client.clientDisplayName,
      clientId: client.clientId,
      maxLifetimeSeconds: 300,
      operation,
      requestOrigin: client.requestOrigin,
      registryReleaseSha256: this.releaseSha256,
    });
  }
}
