import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

import {
  ERRORS,
  exactObject,
  isBase64url32,
  isLowerHex64,
  jcs,
  readJsonBody,
  RelayError,
  relayError,
  sha256Base64urlAscii,
  sha256Hex,
} from './json.js';
import { ClientRegistry } from './registry.js';
import { RelayStore, type StoreOutcome, type StoredTransaction } from './store.js';

interface WireModule {
  parseAssetReviewAuthorityActivationRequest(value: unknown): unknown;
  parseAssetReviewAuthorityActivationResult(value: unknown): unknown;
  parseAssetReviewDecisionRequest(value: unknown): unknown;
  parseAssetReviewDecisionResult(value: unknown): unknown;
  parseSdnLoginV1Request(value: unknown): unknown;
  parseSdnLoginV1Result(value: unknown): unknown;
  parseSdnLoginV2Request(value: unknown): unknown;
  parseSdnLoginV2Result(value: unknown): unknown;
  parseWalletAccountRequest(value: unknown): unknown;
  parseWalletAccountResult(value: unknown): unknown;
  parseWalletConnectRequest(value: unknown): unknown;
  parseWalletConnectResult(value: unknown): unknown;
}

const wire = await import(new URL('../../../client/wire.mjs', import.meta.url).href) as WireModule;

const requestParsers: Readonly<Record<string, (value: unknown) => unknown>> = Object.freeze({
  'sdn.asset-review.authority-activation.v1': wire.parseAssetReviewAuthorityActivationRequest,
  'sdn.asset-review.decision.v1': wire.parseAssetReviewDecisionRequest,
  'sdn.auth.jcs-envelope.v2': wire.parseSdnLoginV2Request,
  'sdn.auth.raw-challenge.v1': wire.parseSdnLoginV1Request,
  'sdn.wallet.account.v1': wire.parseWalletAccountRequest,
  'sdn.wallet.connect.v1': wire.parseWalletConnectRequest,
});

const resultParsers: Readonly<Record<string, (value: unknown) => unknown>> = Object.freeze({
  'sdn.asset-review.authority-activation.v1': wire.parseAssetReviewAuthorityActivationResult,
  'sdn.asset-review.decision.v1': wire.parseAssetReviewDecisionResult,
  'sdn.auth.jcs-envelope.v2': wire.parseSdnLoginV2Result,
  'sdn.auth.raw-challenge.v1': wire.parseSdnLoginV1Result,
  'sdn.wallet.account.v1': wire.parseWalletAccountResult,
  'sdn.wallet.connect.v1': wire.parseWalletConnectResult,
});

const TRANSACTION_PATH = /^\/relay\/v1\/transactions\/([0-9a-f]{64})$/u;
const RESULT_PATH = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/result$/u;
const CANCEL_PATH = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/cancel$/u;

export interface RelayServerOptions {
  readonly databasePath: string;
  readonly maxRows?: number;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly rateLimit?: Readonly<{
    bindingMaxRequests?: number;
    coarseMaxRequests?: number;
    maxBuckets?: number;
    maxRequests?: number;
    windowMs: number;
  }>;
  readonly registryPath?: string;
  readonly trustLoopbackProxy?: boolean;
  /** @internal Test-only adapters; production callers should leave this unset. */
  readonly testHooks?: Readonly<{
    clearExpiryTimer?: (handle: unknown) => void;
    directPeerAddress?: (request: IncomingMessage) => string | undefined;
    monotonicNow?: () => number;
    observeSelect?: () => void;
    rawRequestTarget?: (request: IncomingMessage) => string | undefined;
    setExpiryTimer?: (callback: () => void, delayMs: number) => unknown;
  }>;
}

interface RateBucket {
  count: number;
  startedAt: number;
}

class RateLimiter {
  readonly #buckets = new Map<string, RateBucket>();
  readonly #maximumBuckets: number;
  readonly #windowMs: number;

  constructor(configuration: Readonly<{
    maxBuckets?: number;
    windowMs: number;
  }>) {
    const maximumBuckets = configuration.maxBuckets ?? 2048;
    if (!Number.isSafeInteger(maximumBuckets) || maximumBuckets < 16
        || maximumBuckets > 65_536
        || !Number.isSafeInteger(configuration.windowMs) || configuration.windowMs < 1
        || configuration.windowMs > 3_600_000) {
      throw new TypeError('rate limit configuration is invalid');
    }
    this.#maximumBuckets = maximumBuckets;
    this.#windowMs = configuration.windowMs;
  }

  take(key: string, nowMs: number, maximum: number): void {
    const previous = this.#buckets.get(key);
    if (previous && nowMs - previous.startedAt < this.#windowMs) {
      if (previous.count >= maximum) throw relayError(ERRORS.rateLimited);
      previous.count += 1;
      return;
    }
    if (!previous && this.#buckets.size >= this.#maximumBuckets) {
      for (const [candidate, bucket] of this.#buckets) {
        if (nowMs - bucket.startedAt >= this.#windowMs) this.#buckets.delete(candidate);
      }
      if (this.#buckets.size >= this.#maximumBuckets) throw relayError(ERRORS.rateLimited);
    }
    if (!previous) {
      this.#buckets.set(key, { count: 1, startedAt: nowMs });
      return;
    }
    previous.count = 1;
    previous.startedAt = nowMs;
  }
}

function requestOrigin(request: IncomingMessage): string | undefined {
  const value = request.headers.origin;
  return typeof value === 'string' ? value : undefined;
}

function addCors(headers: Record<string, string | number>, origin: string | undefined): void {
  if (!origin) return;
  headers['Access-Control-Allow-Origin'] = origin;
  headers.Vary = 'Origin';
}

function writeJson(
  response: ServerResponse,
  status: number,
  value: unknown,
  corsOrigin?: string,
): void {
  const body = Buffer.from(jcs(value), 'utf8');
  const headers: Record<string, string | number> = {
    'Cache-Control': 'no-store',
    'Content-Length': body.byteLength,
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  };
  addCors(headers, corsOrigin);
  response.writeHead(status, headers);
  response.end(body);
}

function writeEmpty(response: ServerResponse, corsOrigin?: string): void {
  const headers: Record<string, string | number> = {
    'Cache-Control': 'no-store',
    'Content-Length': 0,
    'X-Content-Type-Options': 'nosniff',
  };
  addCors(headers, corsOrigin);
  response.writeHead(204, headers);
  response.end();
}

function errorForOutcome(outcome: Exclude<StoreOutcome<unknown>, { kind: 'ok' }>): RelayError {
  switch (outcome.kind) {
    case 'conflict': return relayError(ERRORS.conflict);
    case 'full': return relayError(ERRORS.rateLimited);
    case 'gone': return relayError(ERRORS.gone);
    case 'invalid-binding': return relayError(ERRORS.invalidBinding);
    case 'not-found': return relayError(ERRORS.notFound);
    case 'unregistered': return relayError(ERRORS.unregistered);
  }
}

function unwrap<T>(outcome: StoreOutcome<T>): T {
  if (outcome.kind === 'ok') return outcome.value;
  throw errorForOutcome(outcome);
}

function entropy(randomBytes: (length: number) => Uint8Array, encoding: 'hex' | 'base64url'): string {
  const value = randomBytes(32);
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
    throw new Error('relay CSPRNG returned an invalid buffer');
  }
  const copy = Buffer.from(value);
  return copy.toString(encoding);
}

function parseWith<T>(parser: (value: unknown) => T, value: unknown): T {
  try {
    return parser(value);
  } catch {
    throw relayError(ERRORS.malformed);
  }
}

function requireLowerHex64(value: unknown): string {
  if (!isLowerHex64(value)) throw relayError(ERRORS.malformed);
  return value;
}

function requireBase64url32(value: unknown): string {
  if (!isBase64url32(value)) throw relayError(ERRORS.malformed);
  return value;
}

function transactionResponse(transaction: StoredTransaction): unknown {
  if (transaction.requestJson === null || transaction.resultToken === null) {
    throw relayError(ERRORS.conflict);
  }
  return {
    callbackUri: transaction.callbackUri,
    clientDisplayName: transaction.clientDisplayName,
    clientId: transaction.clientId,
    expiresAt: new Date(transaction.expiresAtMs).toISOString(),
    operation: transaction.operation,
    registryVersion: transaction.registryVersion,
    request: JSON.parse(transaction.requestJson) as unknown,
    requestOrigin: transaction.requestOrigin,
    requestSha256: transaction.requestSha256,
    resultToken: transaction.resultToken,
    schemaVersion: 1,
    state: transaction.state,
    transactionId: transaction.transactionId,
  };
}

function isPostRoute(pathname: string): boolean {
  return pathname === '/relay/v1/transactions'
    || pathname === '/relay/v1/codes/redeem'
    || RESULT_PATH.test(pathname)
    || CANCEL_PATH.test(pathname);
}

function rateRoute(method: string | undefined, pathname: string): string | undefined {
  if (method === 'GET' && TRANSACTION_PATH.test(pathname)) return 'transaction-get';
  if ((method === 'POST' || method === 'OPTIONS') && pathname === '/relay/v1/transactions') {
    return 'transaction-create';
  }
  if ((method === 'POST' || method === 'OPTIONS') && RESULT_PATH.test(pathname)) {
    return 'transaction-result';
  }
  if ((method === 'POST' || method === 'OPTIONS') && CANCEL_PATH.test(pathname)) {
    return 'transaction-cancel';
  }
  if ((method === 'POST' || method === 'OPTIONS') && pathname === '/relay/v1/codes/redeem') {
    return 'code-redeem';
  }
  return undefined;
}

interface ParsedRequestTarget {
  readonly hasFragment: boolean;
  readonly hasQuery: boolean;
  readonly malformedSuffix: boolean;
  readonly pathname: string;
}

function parseRequestTarget(value: string | undefined): ParsedRequestTarget | undefined {
  if (typeof value !== 'string' || value.length === 0
      || !value.startsWith('/') || value.startsWith('//')) {
    return undefined;
  }
  let separator = -1;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === '?' || character === '#') {
      separator = index;
      break;
    }
    if (index >= 8192) return undefined;
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e || code === 0x5c) return undefined;
  }
  const pathname = value.slice(0, separator === -1 ? value.length : separator);
  if (pathname.length === 0 || pathname.includes('%') || pathname.includes('//')) return undefined;
  for (const segment of pathname.split('/')) {
    if (segment === '.' || segment === '..') return undefined;
  }

  let hasQuery = false;
  let hasFragment = false;
  let malformedSuffix = false;
  if (separator === -1) {
    return { hasFragment, hasQuery, malformedSuffix, pathname };
  }
  if (value[separator] === '?') hasQuery = true;
  else hasFragment = true;
  if (value.length - separator - 1 > 8192) {
    malformedSuffix = true;
    return { hasFragment, hasQuery, malformedSuffix, pathname };
  }
  for (let index = separator + 1; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e || code === 0x5c) {
      malformedSuffix = true;
      break;
    }
    if (value[index] === '?' && !hasQuery && !hasFragment) {
      hasQuery = true;
    } else if (value[index] === '#' && !hasFragment) {
      hasFragment = true;
    }
    if (value[index] !== '%') continue;
    const encoded = value.slice(index + 1, index + 3);
    if (!/^[0-9A-Fa-f]{2}$/u.test(encoded)) {
      malformedSuffix = true;
      break;
    }
    index += 2;
  }
  return { hasFragment, hasQuery, malformedSuffix, pathname };
}

function canonicalIpAddress(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > 45
      || value.trim() !== value || value.includes(',') || isIP(value) === 0) {
    return undefined;
  }
  if (isIP(value) === 4) {
    return value.split('.').map((part) => String(Number(part))).join('.');
  }
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    const canonical = hostname.slice(1, -1).toLowerCase();
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u.exec(canonical);
    if (!mapped?.[1] || !mapped[2]) return canonical;
    const high = Number.parseInt(mapped[1], 16);
    const low = Number.parseInt(mapped[2], 16);
    return `::ffff:${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
  } catch {
    return undefined;
  }
}

function isLoopbackAddress(address: string): boolean {
  if (address === '::1') return true;
  const ipv4 = address.startsWith('::ffff:') ? address.slice('::ffff:'.length) : address;
  return isIP(ipv4) === 4 && Number(ipv4.split('.')[0]) === 127;
}

function peerAddress(
  request: IncomingMessage,
  trustLoopbackProxy: boolean,
  directPeerAddress?: (request: IncomingMessage) => string | undefined,
): string {
  const direct = canonicalIpAddress(directPeerAddress?.(request) ?? request.socket.remoteAddress);
  if (!direct) return 'unknown-peer';
  if (!trustLoopbackProxy || !isLoopbackAddress(direct)) return direct;
  const forwarded = canonicalIpAddress(request.headers['x-real-ip']);
  return forwarded ?? direct;
}

function requireRequestMaximum(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 10_000) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function defaultMonotonicNow(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

export function createRelayServer(options: RelayServerOptions): Server {
  if (!options || typeof options.databasePath !== 'string' || options.databasePath.length === 0) {
    throw new TypeError('databasePath is required');
  }
  if (options.trustLoopbackProxy !== undefined && typeof options.trustLoopbackProxy !== 'boolean') {
    throw new TypeError('trustLoopbackProxy is invalid');
  }
  const now = options.now ?? Date.now;
  const monotonicNow = options.testHooks?.monotonicNow ?? defaultMonotonicNow;
  const randomBytes = options.randomBytes ?? nodeRandomBytes;
  const registry = new ClientRegistry(options.registryPath);
  const store = new RelayStore(options.databasePath, options.maxRows, options.testHooks?.observeSelect);
  const rateLimit = options.rateLimit ?? { windowMs: 30_000 };
  const sharedMaximum = rateLimit.maxRequests;
  const coarseMaximum = requireRequestMaximum(
    rateLimit.coarseMaxRequests ?? sharedMaximum ?? 600,
    'coarseMaxRequests',
  );
  const bindingMaximum = requireRequestMaximum(
    rateLimit.bindingMaxRequests ?? sharedMaximum ?? 120,
    'bindingMaxRequests',
  );
  const limiter = new RateLimiter({
    maxBuckets: rateLimit.maxBuckets,
    windowMs: rateLimit.windowMs,
  });
  const expiryTimers = new Set<unknown>();
  const setExpiryTimer = options.testHooks?.setExpiryTimer ?? ((callback, delayMs) => {
    const timer = setTimeout(callback, delayMs);
    timer.unref();
    return timer;
  });
  const clearExpiryTimer = options.testHooks?.clearExpiryTimer ?? ((handle) => {
    clearTimeout(handle as NodeJS.Timeout);
  });

  const scheduleExpiry = (expiresAtMs: number, createdAtMs: number): void => {
    let timer: unknown;
    timer = setExpiryTimer(() => {
      expiryTimers.delete(timer);
      // The callback represents the captured deadline even if the wall clock rolls backward.
      store.expire(Math.max(now(), expiresAtMs));
    }, Math.max(0, expiresAtMs - createdAtMs));
    expiryTimers.add(timer);
  };

  const server = createServer(async (request, response) => {
    let corsOrigin: string | undefined;
    try {
      const rawTarget = options.testHooks?.rawRequestTarget?.(request) ?? request.url;
      const target = parseRequestTarget(rawTarget);
      if (!target) throw relayError(ERRORS.notFound);
      const { pathname } = target;
      const routeBucket = rateRoute(request.method, pathname);
      let ratePeer: string | undefined;
      if (routeBucket) {
        ratePeer = peerAddress(
          request,
          options.trustLoopbackProxy ?? false,
          options.testHooks?.directPeerAddress,
        );
        // This fixed route/peer bucket is always charged before any SQLite lookup.
        limiter.take(`coarse\0${routeBucket}\0peer\0${ratePeer}`, monotonicNow(), coarseMaximum);

        if (!target.hasQuery && !target.hasFragment && !target.malformedSuffix
            && routeBucket === 'transaction-get') {
          const transactionId = TRANSACTION_PATH.exec(pathname)?.[1];
          const transaction = transactionId ? store.peek(transactionId) : undefined;
          const subject = transaction
            ? `binding\0${transaction.requestOrigin}\0${transaction.clientId}`
            : 'absent';
          limiter.take(
            `binding\0transaction-get\0peer\0${ratePeer}\0${subject}`,
            monotonicNow(),
            bindingMaximum,
          );
        }
      }
      if (target.hasQuery || target.hasFragment || target.malformedSuffix) {
        throw relayError(ERRORS.notFound);
      }
      const origin = requestOrigin(request);

      if (request.method === 'GET' && pathname === '/healthz') {
        writeJson(response, 200, { schemaVersion: 1, status: 'ok' });
        return;
      }

      const getMatch = request.method === 'GET' ? TRANSACTION_PATH.exec(pathname) : null;
      if (getMatch) {
        const transactionId = getMatch[1];
        if (!transactionId) throw relayError(ERRORS.notFound);
        const transaction = unwrap(store.get(transactionId, now()));
        writeJson(response, 200, transactionResponse(transaction));
        return;
      }

      if (request.method === 'OPTIONS' && isPostRoute(pathname)) {
        if (!origin || !registry.hasOrigin(origin)) throw relayError(ERRORS.unregistered);
        const requestedMethod = request.headers['access-control-request-method'];
        if (requestedMethod !== undefined && requestedMethod !== 'POST') throw relayError(ERRORS.malformed);
        const resultOrCancel = RESULT_PATH.exec(pathname) ?? CANCEL_PATH.exec(pathname);
        if (resultOrCancel) {
          const transactionId = resultOrCancel[1];
          const transaction = transactionId ? store.peek(transactionId) : undefined;
          if (!transaction || transaction.requestOrigin !== origin) throw relayError(ERRORS.unregistered);
        }
        response.writeHead(204, {
          'Access-Control-Allow-Headers': 'content-type',
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Max-Age': '300',
          'Cache-Control': 'no-store',
          'Content-Length': '0',
          Vary: 'Origin',
        });
        response.end();
        return;
      }

      if (request.method === 'POST' && pathname === '/relay/v1/transactions') {
        const body = exactObject(await readJsonBody(request, 32 * 1024), [
          'clientId',
          'codeChallenge',
          'codeChallengeMethod',
          'operation',
          'request',
          'schemaVersion',
          'state',
          'transactionId',
        ]);
        if (body.schemaVersion !== 1 || body.codeChallengeMethod !== 'S256') {
          throw relayError(ERRORS.malformed);
        }
        const transactionId = requireLowerHex64(body.transactionId);
        const state = requireLowerHex64(body.state);
        const codeChallenge = requireBase64url32(body.codeChallenge);
        const binding = registry.resolve(body.clientId, origin, body.operation);
        const parser = requestParsers[binding.operation];
        if (!parser) throw relayError(ERRORS.unregistered);
        const publicRequest = parseWith(parser, body.request);
        corsOrigin = binding.requestOrigin;
        limiter.take(
          `register\0peer\0${ratePeer ?? 'unknown-peer'}\0${binding.requestOrigin}\0${binding.clientId}`,
          monotonicNow(),
          bindingMaximum,
        );
        const createdAtMs = now();
        const expiresAtMs = createdAtMs + Math.min(binding.maxLifetimeSeconds, 300) * 1000;
        const created = unwrap(store.create({
          binding,
          codeChallenge,
          createdAtMs,
          expiresAtMs,
          requestJson: jcs(publicRequest),
          requestSha256: sha256Hex(jcs(publicRequest)),
          resultToken: entropy(randomBytes, 'base64url'),
          state,
          transactionId,
        }));
        scheduleExpiry(expiresAtMs, createdAtMs);
        writeJson(response, 201, {
          expiresAt: new Date(created.expiresAtMs).toISOString(),
          schemaVersion: 1,
          transactionId: created.transactionId,
        }, corsOrigin);
        return;
      }

      const resultMatch = request.method === 'POST' ? RESULT_PATH.exec(pathname) : null;
      if (resultMatch) {
        const pathTransactionId = resultMatch[1];
        if (!pathTransactionId) throw relayError(ERRORS.notFound);
        const transaction = store.peek(pathTransactionId);
        if (transaction?.requestOrigin === origin) corsOrigin = origin;
        const body = exactObject(await readJsonBody(request, 64 * 1024), [
          'result', 'resultToken', 'schemaVersion', 'transactionId',
        ]);
        if (body.schemaVersion !== 1) throw relayError(ERRORS.malformed);
        const bodyTransactionId = requireLowerHex64(body.transactionId);
        if (bodyTransactionId !== pathTransactionId) throw relayError(ERRORS.invalidBinding);
        const resultToken = requireBase64url32(body.resultToken);
        if (!transaction) throw relayError(ERRORS.notFound);
        const parser = resultParsers[transaction.operation];
        if (!parser) throw relayError(ERRORS.unregistered);
        const publicResult = parseWith(parser, body.result);
        limiter.take(
          `result\0peer\0${ratePeer ?? 'unknown-peer'}\0${transaction.requestOrigin}\0${transaction.clientId}`,
          monotonicNow(),
          bindingMaximum,
        );
        const completed = unwrap(store.complete({
          createAuthorizationCode: () => entropy(randomBytes, 'hex'),
          nowMs: now(),
          resultJson: jcs(publicResult),
          resultSha256: sha256Hex(jcs(publicResult)),
          resultToken,
          transactionId: pathTransactionId,
        }));
        const code = completed.authorizationCode;
        if (!code) throw relayError(ERRORS.internal);
        const redirectUri = `${completed.callbackUri}#code=${encodeURIComponent(code)}&state=${encodeURIComponent(completed.state)}`;
        writeJson(response, 201, {
          redirectUri,
          schemaVersion: 1,
          transactionId: completed.transactionId,
        }, corsOrigin);
        return;
      }

      const cancelMatch = request.method === 'POST' ? CANCEL_PATH.exec(pathname) : null;
      if (cancelMatch) {
        const pathTransactionId = cancelMatch[1];
        if (!pathTransactionId) throw relayError(ERRORS.notFound);
        const transaction = store.peek(pathTransactionId);
        if (transaction && transaction.requestOrigin === origin) {
          corsOrigin = origin;
          limiter.take(
            `cancel\0peer\0${ratePeer ?? 'unknown-peer'}\0${origin}\0${transaction.clientId}`,
            monotonicNow(),
            bindingMaximum,
          );
        }
        const body = exactObject(await readJsonBody(request, 2 * 1024), [
          'codeVerifier', 'schemaVersion', 'state', 'transactionId',
        ]);
        if (body.schemaVersion !== 1) throw relayError(ERRORS.malformed);
        const bodyTransactionId = requireLowerHex64(body.transactionId);
        const state = requireLowerHex64(body.state);
        const codeVerifier = requireBase64url32(body.codeVerifier);
        if (!origin || !registry.hasOrigin(origin)) throw relayError(ERRORS.unregistered);
        unwrap(store.cancel({
          bodyTransactionId,
          codeChallenge: sha256Base64urlAscii(codeVerifier),
          nowMs: now(),
          pathTransactionId,
          requestOrigin: origin,
          state,
        }));
        writeEmpty(response, corsOrigin);
        return;
      }

      if (request.method === 'POST' && pathname === '/relay/v1/codes/redeem') {
        const body = exactObject(await readJsonBody(request, 2 * 1024), [
          'code', 'codeVerifier', 'schemaVersion', 'state', 'transactionId',
        ]);
        if (body.schemaVersion !== 1) throw relayError(ERRORS.malformed);
        const code = requireLowerHex64(body.code);
        const codeVerifier = requireBase64url32(body.codeVerifier);
        const state = requireLowerHex64(body.state);
        const transactionId = requireLowerHex64(body.transactionId);
        if (!origin || !registry.hasOrigin(origin)) throw relayError(ERRORS.unregistered);
        const transaction = store.peek(transactionId);
        if (transaction && transaction.requestOrigin === origin) {
          corsOrigin = origin;
          limiter.take(
            `redeem\0peer\0${ratePeer ?? 'unknown-peer'}\0${origin}\0${transaction.clientId}`,
            monotonicNow(),
            bindingMaximum,
          );
        }
        const redeemed = unwrap(store.redeem({
          code,
          codeChallenge: sha256Base64urlAscii(codeVerifier),
          nowMs: now(),
          requestOrigin: origin,
          state,
          transactionId,
        }));
        writeJson(response, 200, {
          result: JSON.parse(redeemed.resultJson) as unknown,
          schemaVersion: 1,
          transactionId: redeemed.transaction.transactionId,
        }, corsOrigin);
        return;
      }

      throw relayError(ERRORS.notFound);
    } catch (error) {
      const safe = error instanceof RelayError ? error : relayError(ERRORS.internal);
      if (!response.headersSent) {
        writeJson(response, safe.status, {
          error: { code: safe.code, message: safe.message },
          schemaVersion: 1,
        }, corsOrigin);
      } else {
        response.destroy();
      }
    }
  });

  server.once('close', () => {
    for (const timer of expiryTimers) clearExpiryTimer(timer);
    expiryTimers.clear();
    store.close();
  });
  return server;
}

function startFromEnvironment(): void {
  const databasePath = process.env.SDN_WALLET_RELAY_DATABASE_PATH ?? '/run/sdn-wallet-relay/relay.sqlite';
  const host = process.env.SDN_WALLET_RELAY_HOST ?? '127.0.0.1';
  const portText = process.env.SDN_WALLET_RELAY_PORT ?? '8787';
  const trustLoopbackProxyText = process.env.SDN_WALLET_RELAY_TRUST_LOOPBACK_X_REAL_IP ?? '0';
  if (!/^(?:[1-9]\d{0,4})$/u.test(portText)) throw new Error('relay port is invalid');
  const port = Number(portText);
  if (port > 65535) throw new Error('relay port is invalid');
  if (trustLoopbackProxyText !== '0' && trustLoopbackProxyText !== '1') {
    throw new Error('relay loopback proxy trust setting is invalid');
  }
  // Enable only when the loopback Nginx hop overwrites or strips inbound X-Real-IP.
  const server = createRelayServer({
    databasePath,
    trustLoopbackProxy: trustLoopbackProxyText === '1',
  });
  server.listen(port, host);
  const stop = (): void => {
    server.close();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  startFromEnvironment();
}
