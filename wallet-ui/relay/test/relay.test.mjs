import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createRelayServer } from '../dist/src/server.js';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

const FIXED_NOW = Date.parse('2026-07-21T00:00:00.000Z');
const UNKNOWN_ID = 'f'.repeat(64);
const WRONG_STATE = 'e'.repeat(64);
const WRONG_TOKEN = Buffer.alloc(32, 0xee).toString('base64url');
const WRONG_VERIFIER = Buffer.alloc(32, 0xef).toString('base64url');
const OTHER_REGISTERED_ORIGIN = 'https://spaceaware.io';

const flow = JSON.parse(await readFile(new URL('./fixtures/account-flow.json', import.meta.url), 'utf8'));
const errors = JSON.parse(await readFile(new URL('./fixtures/errors.json', import.meta.url), 'utf8'));
const operationPairs = JSON.parse(await readFile(
  new URL('./fixtures/operation-pairs.json', import.meta.url),
  'utf8',
));

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function deterministicRandom(sequence = [0xaa, 0xbb, 0xcc, 0xdd, 0x91, 0x92, 0x93, 0x94]) {
  let offset = 0;
  return (length) => {
    assert.equal(length, 32, 'relay entropy requests are exactly 32 bytes');
    const byte = sequence[offset] ?? ((offset + 1) & 0xff);
    offset += 1;
    return Buffer.alloc(length, byte);
  };
}

function clone(value) {
  return structuredClone(value);
}

function jsonBody(value) {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function makeRegistration({
  transactionId = flow.registration.transactionId,
  state = flow.registration.state,
  codeChallenge = flow.registration.codeChallenge,
  clientId = flow.registration.clientId,
  operation = flow.registration.operation,
  request = {},
} = {}) {
  return {
    clientId,
    codeChallenge,
    codeChallengeMethod: 'S256',
    operation,
    request,
    schemaVersion: 1,
    state,
    transactionId,
  };
}

async function request(baseUrl, {
  method = 'GET',
  pathname = '/',
  rawPath,
  origin,
  body,
  contentType,
  headers = {},
} = {}) {
  const target = new URL(pathname, baseUrl);
  assert.equal(target.hostname, '127.0.0.1', 'tests make local HTTP requests only');
  if (rawPath !== undefined) {
    assert.equal(typeof rawPath, 'string');
  }
  const requestHeaders = { ...headers };
  if (origin !== undefined) requestHeaders.Origin = origin;
  if (body !== undefined) {
    requestHeaders['Content-Type'] = contentType ?? 'application/json';
    requestHeaders['Content-Length'] = Buffer.byteLength(body);
  }
  return new Promise((resolve, reject) => {
    const destination = {
      hostname: target.hostname,
      method,
      path: rawPath ?? `${target.pathname}${target.search}`,
      port: target.port,
      protocol: target.protocol,
      headers: requestHeaders,
    };
    const req = http.request(destination, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const raw = Buffer.concat(chunks);
        let json;
        if (raw.length > 0 && response.headers['content-type']?.startsWith('application/json')) {
          json = JSON.parse(raw.toString('utf8'));
        }
        resolve({
          status: response.statusCode,
          headers: response.headers,
          raw,
          text: raw.toString('utf8'),
          json,
        });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

async function startHarness({
  databasePath,
  now = () => FIXED_NOW,
  monotonicNow = now,
  randomBytes = deterministicRandom(),
  rateLimit,
  maxRows,
  trustLoopbackProxy = false,
  testHooks = {},
} = {}) {
  const directory = databasePath ? null : await mkdtemp(path.join(os.tmpdir(), 'sdn-wallet-relay-test-'));
  const resolvedDatabasePath = databasePath ?? path.join(directory, 'relay.sqlite');
  const server = createRelayServer({
    databasePath: resolvedDatabasePath,
    maxRows,
    now,
    randomBytes,
    rateLimit,
    trustLoopbackProxy,
    testHooks: {
      monotonicNow,
      ...testHooks,
    },
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert(address && typeof address === 'object');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    databasePath: resolvedDatabasePath,
    async close({ removeDirectory = true } = {}) {
      await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
      if (directory && removeDirectory) await rm(directory, { recursive: true, force: true });
    },
    directory,
    server,
  };
}

async function register(harness, registration = flow.registration, origin = flow.origin) {
  return request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin,
    body: jsonBody(registration),
  });
}

async function submitResult(harness, submission = flow.resultSubmission, origin) {
  return request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${submission.transactionId}/result`,
    origin,
    body: jsonBody(submission),
  });
}

async function redeem(harness, submission = flow.redeemSubmission, origin = flow.origin) {
  return request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/codes/redeem',
    origin,
    body: jsonBody(submission),
  });
}

function assertCors(response, origin) {
  assert.equal(response.headers['access-control-allow-origin'], origin);
  assert.match(response.headers.vary ?? '', /(?:^|,\s*)Origin(?:,|$)/u);
  assert.equal(response.headers['access-control-allow-credentials'], undefined);
  assert.notEqual(response.headers['access-control-allow-origin'], '*');
}

function assertNoCors(response) {
  assert.equal(response.headers['access-control-allow-origin'], undefined);
  assert.equal(response.headers['access-control-allow-credentials'], undefined);
}

function assertJsonResponse(response, status, value) {
  assert.equal(response.status, status);
  assert.equal(response.headers['content-type'], 'application/json; charset=utf-8');
  assert.deepEqual(response.json, value);
  assert.equal(response.text, jcs(value));
}

test('serves only the exact route table and health contract', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const health = await request(harness.baseUrl, { pathname: '/healthz' });
  assertJsonResponse(health, 200, { schemaVersion: 1, status: 'ok' });
  assertNoCors(health);

  for (const [method, pathname] of [
    ['POST', '/healthz'],
    ['GET', '/relay/v1/transactions'],
    ['GET', '/relay/v1/codes/redeem'],
    ['OPTIONS', '/healthz'],
    ['OPTIONS', `/relay/v1/transactions/${UNKNOWN_ID}`],
    ['PUT', `/relay/v1/transactions/${UNKNOWN_ID}/result`],
    ['POST', '/relay/v2/transactions'],
    ['GET', '/metrics'],
    ['GET', '/'],
  ]) {
    const response = await request(harness.baseUrl, { method, pathname });
    assertJsonResponse(response, 404, errors.notFound);
  }
});

test('charges all five exact route families before rejecting query or raw-fragment targets', async (t) => {
  const harness = await startHarness({
    rateLimit: { maxRequests: 1, windowMs: 30_000 },
  });
  t.after(() => harness.close());
  const cases = [
    {
      method: 'POST',
      rawPath: '/relay/v1/transactions?unexpected=1',
      origin: flow.origin,
      body: jsonBody(flow.registration),
    },
    {
      method: 'GET',
      rawPath: `/relay/v1/transactions/${UNKNOWN_ID}#unexpected`,
    },
    {
      method: 'POST',
      rawPath: `/relay/v1/transactions/${UNKNOWN_ID}/result?unexpected=1`,
      body: jsonBody({ ...flow.resultSubmission, transactionId: UNKNOWN_ID }),
    },
    {
      method: 'POST',
      rawPath: `/relay/v1/transactions/${UNKNOWN_ID}/cancel#unexpected`,
      origin: flow.origin,
      body: jsonBody({
        codeVerifier: flow.redeemSubmission.codeVerifier,
        schemaVersion: 1,
        state: flow.registration.state,
        transactionId: UNKNOWN_ID,
      }),
    },
    {
      method: 'POST',
      rawPath: '/relay/v1/codes/redeem?unexpected=1',
      origin: flow.origin,
      body: jsonBody({
        ...flow.redeemSubmission,
        code: 'd'.repeat(64),
        transactionId: UNKNOWN_ID,
      }),
    },
  ];
  for (const input of cases) {
    const first = await request(harness.baseUrl, input);
    assertJsonResponse(first, 404, errors.notFound);
    assertNoCors(first);
    const repeated = await request(harness.baseUrl, input);
    assertJsonResponse(repeated, 429, errors.rateLimited);
    assertNoCors(repeated);
  }
});

test('shares each POST route coarse bucket with OPTIONS before lookup or parsing', async (t) => {
  let selects = 0;
  const harness = await startHarness({
    rateLimit: { maxRequests: 1, windowMs: 30_000 },
    testHooks: {
      observeSelect() {
        selects += 1;
      },
    },
  });
  t.after(() => harness.close());
  for (const rawPath of [
    '/relay/v1/transactions?options-probe=1',
    `/relay/v1/transactions/${UNKNOWN_ID}/result?options-probe=1`,
    `/relay/v1/transactions/${UNKNOWN_ID}/cancel?options-probe=1`,
    '/relay/v1/codes/redeem?options-probe=1',
  ]) {
    assertJsonResponse(await request(harness.baseUrl, {
      method: 'OPTIONS',
      rawPath,
    }), 404, errors.notFound);
    assertJsonResponse(await request(harness.baseUrl, {
      method: 'POST',
      rawPath,
    }), 429, errors.rateLimited);
  }
  assert.equal(selects, 0);
});

test('coarse-charges every recognized pathname before rejecting malformed or oversized suffixes', async (t) => {
  let injectedTarget = '/';
  let selects = 0;
  const harness = await startHarness({
    rateLimit: { maxRequests: 1, windowMs: 30_000 },
    trustLoopbackProxy: true,
    testHooks: {
      observeSelect() {
        selects += 1;
      },
      rawRequestTarget() {
        return injectedTarget;
      },
    },
  });
  t.after(() => harness.close());
  const routes = [
    ['POST', '/relay/v1/transactions'],
    ['OPTIONS', '/relay/v1/transactions'],
    ['GET', `/relay/v1/transactions/${UNKNOWN_ID}`],
    ['POST', `/relay/v1/transactions/${UNKNOWN_ID}/result`],
    ['OPTIONS', `/relay/v1/transactions/${UNKNOWN_ID}/result`],
    ['POST', `/relay/v1/transactions/${UNKNOWN_ID}/cancel`],
    ['OPTIONS', `/relay/v1/transactions/${UNKNOWN_ID}/cancel`],
    ['POST', '/relay/v1/codes/redeem'],
    ['OPTIONS', '/relay/v1/codes/redeem'],
  ];
  const suffixes = [
    '?bad=\\',
    '#bad=\\',
    `?bad=${String.fromCharCode(0x1f)}`,
    `#bad=${String.fromCharCode(0x1f)}`,
    '?bad=é',
    '#bad=é',
    '?bad=%ZZ',
    '#bad=%ZZ',
    `?bad=${'a'.repeat(8192)}`,
    `#bad=${'a'.repeat(8192)}`,
  ];
  let peer = 1;
  for (const [method, pathname] of routes) {
    for (const suffix of suffixes) {
      injectedTarget = `${pathname}${suffix}`;
      const input = {
        headers: { 'X-Real-IP': `198.51.100.${peer}` },
        method,
        rawPath: '/target-probe',
      };
      peer += 1;
      assertJsonResponse(await request(harness.baseUrl, input), 404, errors.notFound);
      assertJsonResponse(await request(harness.baseUrl, input), 429, errors.rateLimited);
    }
  }
  injectedTarget = undefined;
  for (const suffix of [
    '?bad=\\',
    '#bad=\\',
    '?bad=%ZZ',
    '#bad=%ZZ',
    `?bad=${'a'.repeat(8192)}`,
    `#bad=${'a'.repeat(8192)}`,
  ]) {
    const input = {
      headers: { 'X-Real-IP': `198.51.100.${peer}` },
      method: 'POST',
      rawPath: `/relay/v1/transactions${suffix}`,
    };
    peer += 1;
    assertJsonResponse(await request(harness.baseUrl, input), 404, errors.notFound);
    assertJsonResponse(await request(harness.baseUrl, input), 429, errors.rateLimited);
  }
  assert.equal(selects, 0);
});

test('rejects non-canonical raw request targets before WHATWG path normalization can alias a route', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  const aliases = [
    '/relay/v1/not-a-route/../transactions',
    '/relay\\v1\\transactions',
    '/relay/v1/%2e%2e/transactions',
    '/relay%2fv1/transactions',
    '/relay%5cv1/transactions',
    'http://wallet-relay.invalid/relay/v1/transactions',
    '//wallet-relay.invalid/relay/v1/transactions',
    '/relay//v1/transactions',
    '/relay/v1/transactions%ZZ',
  ];
  for (const [index, rawPath] of aliases.entries()) {
    const marker = (0x80 + index).toString(16).padStart(2, '0');
    const registration = makeRegistration({
      state: marker.repeat(32),
      transactionId: marker.repeat(32),
    });
    const response = await request(harness.baseUrl, {
      method: 'POST',
      rawPath,
      origin: flow.origin,
      body: jsonBody(registration),
    });
    assertJsonResponse(response, 404, errors.notFound);
    assertNoCors(response);
  }
  assert.equal((await register(harness)).status, 201);
});

test('completes the committed no-opener PKCE fixture and erases public bodies on redemption', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const preflight = await request(harness.baseUrl, {
    method: 'OPTIONS',
    pathname: '/relay/v1/transactions',
    origin: flow.origin,
    headers: {
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.raw.length, 0);
  assertCors(preflight, flow.origin);
  assert.equal(preflight.headers['access-control-allow-methods'], 'POST');
  assert.equal(preflight.headers['access-control-allow-headers'], 'content-type');

  const registered = await register(harness);
  assertJsonResponse(registered, 201, flow.registrationResponse);
  assertCors(registered, flow.origin);

  const fetched = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${flow.registration.transactionId}`,
    origin: flow.origin,
  });
  assertJsonResponse(fetched, 200, flow.transactionResponse);
  assertNoCors(fetched);

  const completed = await submitResult(harness);
  assertJsonResponse(completed, 201, flow.resultResponse);
  assertNoCors(completed);

  const redeemed = await redeem(harness);
  assertJsonResponse(redeemed, 200, flow.redeemResponse);
  assertCors(redeemed, flow.origin);

  const database = new Database(harness.databasePath, { readonly: true });
  const row = database.prepare(`
    SELECT request_json, result_json, result_token, authorization_code
      FROM relay_transactions WHERE transaction_id = ?
  `).get(flow.registration.transactionId);
  database.close();
  assert.deepEqual(row, {
    request_json: null,
    result_json: null,
    result_token: null,
    authorization_code: null,
  });

  const replay = await redeem(harness);
  assertJsonResponse(replay, 409, errors.conflict);
  assertCors(replay, flow.origin);
});

test('rejects wrong media types, excess bytes, malformed UTF-8, duplicates, and unknown fields', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const wrongMedia = await request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: flow.origin,
    contentType: 'text/plain',
    body: jsonBody(flow.registration),
  });
  assertJsonResponse(wrongMedia, 415, errors.unsupportedMediaType);
  assertNoCors(wrongMedia);

  for (const [pathname, bytes] of [
    ['/relay/v1/transactions', 32 * 1024 + 1],
    [`/relay/v1/transactions/${UNKNOWN_ID}/result`, 64 * 1024 + 1],
    [`/relay/v1/transactions/${UNKNOWN_ID}/cancel`, 2 * 1024 + 1],
    ['/relay/v1/codes/redeem', 2 * 1024 + 1],
  ]) {
    const oversized = await request(harness.baseUrl, {
      method: 'POST',
      pathname,
      origin: flow.origin,
      body: Buffer.alloc(bytes, 0x20),
    });
    assertJsonResponse(oversized, 413, errors.payloadTooLarge);
    assert.ok(oversized.raw.length < 256);
  }

  for (const body of [
    Buffer.from('{', 'utf8'),
    Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]),
    Buffer.from('{"clientId":"sdn-landing-web-v1","clientId":"attacker","codeChallenge":"KPlDz_s5_TfmJIOULW1xN9xQeIvZ3e0Wj3nQKHXecd8","codeChallengeMethod":"S256","operation":"sdn.wallet.account.v1","request":{},"schemaVersion":1,"state":"2222222222222222222222222222222222222222222222222222222222222222","transactionId":"1111111111111111111111111111111111111111111111111111111111111111"}'),
    Buffer.from('{"clientId":"sdn-landing-web-v1","codeChallenge":"KPlDz_s5_TfmJIOULW1xN9xQeIvZ3e0Wj3nQKHXecd8","codeChallengeMethod":"S256","operation":"sdn.wallet.account.v1","request":{"x":1,"x":2},"schemaVersion":1,"state":"2222222222222222222222222222222222222222222222222222222222222222","transactionId":"1111111111111111111111111111111111111111111111111111111111111111"}'),
  ]) {
    const malformed = await request(harness.baseUrl, {
      method: 'POST',
      pathname: '/relay/v1/transactions',
      origin: flow.origin,
      body,
    });
    assertJsonResponse(malformed, 400, errors.malformed);
    assert.ok(!malformed.text.includes('attacker'));
  }

  for (const field of ['callbackUri', 'requestOrigin', 'audience', 'credentials', 'seed']) {
    const registration = { ...clone(flow.registration), [field]: `sensitive-${field}` };
    const unknown = await register(harness, registration);
    assertJsonResponse(unknown, 400, errors.malformed);
    assert.ok(!unknown.text.includes(`sensitive-${field}`));
  }
});

test('rejects a raw UTF-8 BOM before decoding or registering the transaction', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  const bomBody = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    jsonBody(flow.registration),
  ]);
  const rejected = await request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: flow.origin,
    body: bomBody,
  });
  assertJsonResponse(rejected, 400, errors.malformed);
  assertNoCors(rejected);
  assert.equal((await register(harness)).status, 201);
});

test('requires an exact registered origin, client, operation, and operation-specific public schema', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  for (const [registration, origin] of [
    [flow.registration, undefined],
    [flow.registration, 'https://attacker.invalid'],
    [makeRegistration({ clientId: 'unknown-client-v1' }), flow.origin],
    [makeRegistration({ operation: 'sdn.auth.jcs-envelope.v2' }), flow.origin],
  ]) {
    const response = origin === undefined
      ? await request(harness.baseUrl, {
        method: 'POST',
        pathname: '/relay/v1/transactions',
        body: jsonBody(registration),
      })
      : await register(harness, registration, origin);
    assertJsonResponse(response, 403, errors.unregistered);
    assertNoCors(response);
  }

  const invalidRequest = await register(harness, makeRegistration({
    transactionId: '3'.repeat(64),
    state: '4'.repeat(64),
    request: { extra: true },
  }));
  assertJsonResponse(invalidRequest, 400, errors.malformed);

  assert.equal((await register(harness)).status, 201);
  const invalidResult = clone(flow.resultSubmission);
  invalidResult.result = { ...invalidResult.result, seedBase64url: 'not-public' };
  const rejectedResult = await submitResult(harness, invalidResult);
  assertJsonResponse(rejectedResult, 400, errors.malformed);
  assert.ok(!rejectedResult.text.includes('seedBase64url'));
});

test('dispatches each of the six committed request/result fixture pairs to only its registered operation', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal(operationPairs.schemaVersion, 1);
  assert.deepEqual(operationPairs.pairs.map(({ operation }) => operation).sort(), [
    'sdn.asset-review.authority-activation.v1',
    'sdn.asset-review.decision.v1',
    'sdn.auth.jcs-envelope.v2',
    'sdn.auth.raw-challenge.v1',
    'sdn.wallet.account.v1',
    'sdn.wallet.connect.v1',
  ]);

  for (const [index, pair] of operationPairs.pairs.entries()) {
    const byte = (0x10 + index).toString(16).padStart(2, '0');
    const stateByte = (0x30 + index).toString(16).padStart(2, '0');
    const verifier = Buffer.alloc(32, 0x50 + index).toString('base64url');
    const codeChallenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    const registration = makeRegistration({
      clientId: pair.clientId,
      codeChallenge,
      operation: pair.operation,
      request: pair.request,
      state: stateByte.repeat(32),
      transactionId: byte.repeat(32),
    });
    const registered = await register(harness, registration, pair.origin);
    assert.equal(registered.status, 201, `${pair.name} registration`);

    const fetched = await request(harness.baseUrl, {
      pathname: `/relay/v1/transactions/${registration.transactionId}`,
    });
    assert.equal(fetched.status, 200, `${pair.name} fetch`);
    assert.equal(fetched.json.operation, pair.operation);
    assert.deepEqual(fetched.json.request, pair.request);

    const completed = await submitResult(harness, {
      result: pair.result,
      resultToken: fetched.json.resultToken,
      schemaVersion: 1,
      transactionId: registration.transactionId,
    });
    assert.equal(completed.status, 201, `${pair.name} completion`);
    const redirect = new URL(completed.json.redirectUri);
    const fragment = new URLSearchParams(redirect.hash.slice(1));
    const code = fragment.get('code');
    assert.match(code, /^[0-9a-f]{64}$/u);
    assert.equal(fragment.get('state'), registration.state);

    const redeemed = await redeem(harness, {
      code,
      codeVerifier: verifier,
      schemaVersion: 1,
      state: registration.state,
      transactionId: registration.transactionId,
    }, pair.origin);
    assert.equal(redeemed.status, 200, `${pair.name} redemption`);
    assert.deepEqual(redeemed.json.result, pair.result);
  }

  const wrongRequest = makeRegistration({
    clientId: 'sdn-landing-web-v1',
    codeChallenge: flow.registration.codeChallenge,
    operation: 'sdn.wallet.account.v1',
    request: operationPairs.pairs.find(({ name }) => name === 'sdn-v1').request,
    state: '8'.repeat(64),
    transactionId: '7'.repeat(64),
  });
  assertJsonResponse(await register(harness, wrongRequest), 400, errors.malformed);

  const accountPair = operationPairs.pairs.find(({ name }) => name === 'account');
  const rawPair = operationPairs.pairs.find(({ name }) => name === 'sdn-v1');
  const accountRegistration = makeRegistration({
    clientId: accountPair.clientId,
    operation: accountPair.operation,
    request: accountPair.request,
    state: 'a'.repeat(64),
    transactionId: '9'.repeat(64),
  });
  assert.equal((await register(harness, accountRegistration, accountPair.origin)).status, 201);
  const fetchedAccount = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${accountRegistration.transactionId}`,
  });
  assertJsonResponse(await submitResult(harness, {
    result: rawPair.result,
    resultToken: fetchedAccount.json.resultToken,
    schemaVersion: 1,
    transactionId: accountRegistration.transactionId,
  }), 400, errors.malformed);
});

test('enforces exclusive registration and reports absent resources without rebinding', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const [left, right] = await Promise.all([register(harness), register(harness)]);
  assert.deepEqual([left.status, right.status].sort(), [201, 409]);
  const conflict = left.status === 409 ? left : right;
  assertJsonResponse(conflict, 409, errors.conflict);

  for (const [method, pathname, body] of [
    ['GET', `/relay/v1/transactions/${UNKNOWN_ID}`, undefined],
    ['POST', `/relay/v1/transactions/${UNKNOWN_ID}/result`, jsonBody({
      ...flow.resultSubmission,
      transactionId: UNKNOWN_ID,
    })],
    ['POST', `/relay/v1/transactions/${UNKNOWN_ID}/cancel`, jsonBody({
      codeVerifier: flow.redeemSubmission.codeVerifier,
      schemaVersion: 1,
      state: flow.registration.state,
      transactionId: UNKNOWN_ID,
    })],
  ]) {
    const response = await request(harness.baseUrl, {
      method,
      pathname,
      origin: flow.origin,
      body,
    });
    assertJsonResponse(response, 404, errors.notFound);
  }
});

test('uses one atomic result and redemption winner under races', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);

  const resultRace = await Promise.all([
    submitResult(harness),
    submitResult(harness),
    submitResult(harness),
    submitResult(harness),
  ]);
  assert.deepEqual(resultRace.map(({ status }) => status).sort(), [201, 409, 409, 409]);
  for (const response of resultRace.filter(({ status }) => status === 409)) {
    assertJsonResponse(response, 409, errors.conflict);
  }

  const redemptionRace = await Promise.all([
    redeem(harness),
    redeem(harness),
    redeem(harness),
    redeem(harness),
  ]);
  assert.deepEqual(redemptionRace.map(({ status }) => status).sort(), [200, 409, 409, 409]);
  for (const response of redemptionRace.filter(({ status }) => status === 409)) {
    assertJsonResponse(response, 409, errors.conflict);
  }
});

test('uses one generic binding error for wrong tokens, state, verifier, transaction binding, and code', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);

  const wrongToken = clone(flow.resultSubmission);
  wrongToken.resultToken = WRONG_TOKEN;
  assertJsonResponse(await submitResult(harness, wrongToken), 400, errors.invalidBinding);
  assert.equal((await submitResult(harness)).status, 201);

  const attempts = [
    { ...flow.redeemSubmission, state: WRONG_STATE },
    { ...flow.redeemSubmission, codeVerifier: WRONG_VERIFIER },
    { ...flow.redeemSubmission, transactionId: UNKNOWN_ID },
    { ...flow.redeemSubmission, code: 'd'.repeat(64) },
  ];
  for (const attempt of attempts) {
    const response = await redeem(harness, attempt);
    assertJsonResponse(response, 400, errors.invalidBinding);
  }

  const wrongOrigin = await redeem(harness, flow.redeemSubmission, 'https://attacker.invalid');
  assertJsonResponse(wrongOrigin, 403, errors.unregistered);
  assertNoCors(wrongOrigin);
  assert.equal((await redeem(harness)).status, 200);
});

test('echoes CORS only after the exact registration or stored transaction/code origin binds', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const mismatchedRegistration = await register(harness, flow.registration, OTHER_REGISTERED_ORIGIN);
  assertJsonResponse(mismatchedRegistration, 403, errors.unregistered);
  assertNoCors(mismatchedRegistration);

  assert.equal((await register(harness)).status, 201);
  const fetched = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${flow.registration.transactionId}`,
    origin: OTHER_REGISTERED_ORIGIN,
  });
  assert.equal(fetched.status, 200);
  assertNoCors(fetched);

  const completed = await submitResult(harness, flow.resultSubmission, OTHER_REGISTERED_ORIGIN);
  assert.equal(completed.status, 201);
  assertNoCors(completed);

  const wrongRedeemOrigin = await redeem(harness, flow.redeemSubmission, OTHER_REGISTERED_ORIGIN);
  assertJsonResponse(wrongRedeemOrigin, 403, errors.unregistered);
  assertNoCors(wrongRedeemOrigin);
  assert.equal((await redeem(harness)).status, 200);

  const cancelRegistration = makeRegistration({
    transactionId: '3'.repeat(64),
    state: '4'.repeat(64),
  });
  assert.equal((await register(harness, cancelRegistration)).status, 201);
  const cancelBody = {
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: cancelRegistration.state,
    transactionId: cancelRegistration.transactionId,
  };
  const wrongCancelOrigin = await request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${cancelRegistration.transactionId}/cancel`,
    origin: OTHER_REGISTERED_ORIGIN,
    body: jsonBody(cancelBody),
  });
  assertJsonResponse(wrongCancelOrigin, 403, errors.unregistered);
  assertNoCors(wrongCancelOrigin);
  const exactCancel = await request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${cancelRegistration.transactionId}/cancel`,
    origin: flow.origin,
    body: jsonBody(cancelBody),
  });
  assert.equal(exactCancel.status, 204);
  assertCors(exactCancel, flow.origin);
});

test('cancels only with the exact origin, path/body ID, state, and verifier and then stays gone', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);

  const cancelBody = {
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: flow.registration.state,
    transactionId: flow.registration.transactionId,
  };
  for (const body of [
    { ...cancelBody, transactionId: UNKNOWN_ID },
    { ...cancelBody, state: WRONG_STATE },
    { ...cancelBody, codeVerifier: WRONG_VERIFIER },
  ]) {
    const response = await request(harness.baseUrl, {
      method: 'POST',
      pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
      origin: flow.origin,
      body: jsonBody(body),
    });
    assertJsonResponse(response, 400, errors.invalidBinding);
  }

  const wrongOrigin = await request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
    origin: 'https://attacker.invalid',
    body: jsonBody(cancelBody),
  });
  assertJsonResponse(wrongOrigin, 403, errors.unregistered);

  const cancelled = await request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
    origin: flow.origin,
    body: jsonBody(cancelBody),
  });
  assert.equal(cancelled.status, 204);
  assert.equal(cancelled.raw.length, 0);
  assertCors(cancelled, flow.origin);

  for (const response of [
    await request(harness.baseUrl, { pathname: `/relay/v1/transactions/${flow.registration.transactionId}` }),
    await submitResult(harness),
    await redeem(harness),
    await request(harness.baseUrl, {
      method: 'POST',
      pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
      origin: flow.origin,
      body: jsonBody(cancelBody),
    }),
  ]) {
    assertJsonResponse(response, 410, errors.gone);
  }
});

test('atomically cancels completed results and completion/cancel races before redemption', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  assert.equal((await submitResult(harness)).status, 201);
  const cancelBody = {
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: flow.registration.state,
    transactionId: flow.registration.transactionId,
  };
  const cancelledCompletion = await request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
    origin: flow.origin,
    body: jsonBody(cancelBody),
  });
  assert.equal(cancelledCompletion.status, 204);
  assertJsonResponse(await redeem(harness), 410, errors.gone);

  const raceRegistration = makeRegistration({
    transactionId: '3'.repeat(64),
    state: '4'.repeat(64),
  });
  assert.equal((await register(harness, raceRegistration)).status, 201);
  const fetched = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${raceRegistration.transactionId}`,
  });
  const raceResult = {
    result: flow.resultSubmission.result,
    resultToken: fetched.json.resultToken,
    schemaVersion: 1,
    transactionId: raceRegistration.transactionId,
  };
  const raceCancel = {
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: raceRegistration.state,
    transactionId: raceRegistration.transactionId,
  };
  const [completion, cancellation] = await Promise.all([
    submitResult(harness, raceResult),
    request(harness.baseUrl, {
      method: 'POST',
      pathname: `/relay/v1/transactions/${raceRegistration.transactionId}/cancel`,
      origin: flow.origin,
      body: jsonBody(raceCancel),
    }),
  ]);
  assert.ok(completion.status === 201 || completion.status === 410);
  assert.equal(cancellation.status, 204);
  const code = completion.status === 201
    ? new URLSearchParams(new URL(completion.json.redirectUri).hash.slice(1)).get('code')
    : 'd'.repeat(64);
  assertJsonResponse(await redeem(harness, {
    code,
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: raceRegistration.state,
    transactionId: raceRegistration.transactionId,
  }), 410, errors.gone);

  const database = new Database(harness.databasePath, { readonly: true });
  const row = database.prepare(`
    SELECT authorization_code, request_json, result_json, result_token, status
      FROM relay_transactions WHERE transaction_id = ?
  `).get(raceRegistration.transactionId);
  database.close();
  assert.deepEqual(row, {
    authorization_code: null,
    request_json: null,
    result_json: null,
    result_token: null,
    status: 'cancelled',
  });
});

test('expires within five minutes, erases bodies, and never revives an expired transaction', async (t) => {
  let now = FIXED_NOW;
  const harness = await startHarness({ now: () => now });
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  now += 300_001;

  for (const response of [
    await request(harness.baseUrl, { pathname: `/relay/v1/transactions/${flow.registration.transactionId}` }),
    await submitResult(harness),
    await request(harness.baseUrl, {
      method: 'POST',
      pathname: `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
      origin: flow.origin,
      body: jsonBody({
        codeVerifier: flow.redeemSubmission.codeVerifier,
        schemaVersion: 1,
        state: flow.registration.state,
        transactionId: flow.registration.transactionId,
      }),
    }),
  ]) {
    assertJsonResponse(response, 410, errors.gone);
  }

  const database = new Database(harness.databasePath, { readonly: true });
  const row = database.prepare('SELECT request_json, result_json, status FROM relay_transactions WHERE transaction_id = ?')
    .get(flow.registration.transactionId);
  database.close();
  assert.deepEqual(row, { request_json: null, result_json: null, status: 'expired' });
  assertJsonResponse(await register(harness), 409, errors.conflict);
});

test('timer expiry erases bodies, token, and code at the captured deadline despite wall-clock rollback', async (t) => {
  let now = FIXED_NOW;
  let scheduled;
  const harness = await startHarness({
    now: () => now,
    testHooks: {
      clearExpiryTimer(handle) {
        handle.cancelled = true;
      },
      setExpiryTimer(callback, delayMs) {
        scheduled = { callback, cancelled: false, delayMs };
        return scheduled;
      },
    },
  });
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  assert.equal((await submitResult(harness)).status, 201);
  assert.equal(scheduled?.delayMs, 300_000);

  const beforeDatabase = new Database(harness.databasePath, { readonly: true });
  const before = beforeDatabase.prepare(`
    SELECT authorization_code, request_json, result_json, result_token, status
      FROM relay_transactions WHERE transaction_id = ?
  `).get(flow.registration.transactionId);
  beforeDatabase.close();
  assert.equal(before.status, 'completed');
  assert.ok(before.authorization_code && before.request_json && before.result_json && before.result_token);

  now = FIXED_NOW - 86_400_000;
  scheduled.callback();

  const afterDatabase = new Database(harness.databasePath, { readonly: true });
  const after = afterDatabase.prepare(`
    SELECT authorization_code, request_json, result_json, result_token, status
      FROM relay_transactions WHERE transaction_id = ?
  `).get(flow.registration.transactionId);
  afterDatabase.close();
  assert.deepEqual(after, {
    authorization_code: null,
    request_json: null,
    result_json: null,
    result_token: null,
    status: 'expired',
  });
});

test('invalidates every transaction and code when the relay restarts on the same SQLite path', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'sdn-wallet-relay-restart-'));
  const databasePath = path.join(directory, 'relay.sqlite');
  try {
    const first = await startHarness({ databasePath });
    assert.equal((await register(first)).status, 201);
    assert.equal((await submitResult(first)).status, 201);
    await first.close({ removeDirectory: false });

    const second = await startHarness({ databasePath });
    try {
      assertJsonResponse(await request(second.baseUrl, {
        pathname: `/relay/v1/transactions/${flow.registration.transactionId}`,
      }), 404, errors.notFound);
      assertJsonResponse(await redeem(second), 404, errors.notFound);
    } finally {
      await second.close({ removeDirectory: false });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('throttles per registered origin and client with a bounded error, then resets its window', async (t) => {
  let now = FIXED_NOW;
  const harness = await startHarness({
    now: () => now,
    rateLimit: { maxRequests: 1, windowMs: 1_000 },
  });
  t.after(() => harness.close());

  assert.equal((await register(harness)).status, 201);
  const second = makeRegistration({ transactionId: '3'.repeat(64), state: '4'.repeat(64) });
  const throttled = await register(harness, second);
  assertJsonResponse(throttled, 429, errors.rateLimited);
  assertNoCors(throttled);
  now += 1_001;
  assert.equal((await register(harness, second)).status, 201);
});

test('bounds GET polling and malformed or absent mutation floods by socket IP and route', async (t) => {
  let now = FIXED_NOW;
  const reads = await startHarness({
    now: () => now,
    rateLimit: { maxRequests: 2, windowMs: 30_000 },
  });
  t.after(() => reads.close());
  assert.equal((await register(reads)).status, 201);
  const getPath = `/relay/v1/transactions/${flow.registration.transactionId}`;
  assert.equal((await request(reads.baseUrl, { pathname: getPath })).status, 200);
  assert.equal((await request(reads.baseUrl, { pathname: getPath })).status, 200);
  assertJsonResponse(await request(reads.baseUrl, { pathname: getPath }), 429, errors.rateLimited);
  now += 30_001;
  assert.equal((await request(reads.baseUrl, { pathname: getPath })).status, 200);

  const floods = await startHarness({
    rateLimit: { maxRequests: 1, windowMs: 30_000 },
  });
  t.after(() => floods.close());
  const malformed = await request(floods.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: 'https://attacker-one.invalid',
    headers: { 'X-Forwarded-For': '198.51.100.1' },
    body: Buffer.from('{', 'utf8'),
  });
  assertJsonResponse(malformed, 400, errors.malformed);
  const changedOriginAndForward = await request(floods.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: 'https://attacker-two.invalid',
    headers: { 'X-Forwarded-For': '203.0.113.9' },
    body: Buffer.from('{', 'utf8'),
  });
  assertJsonResponse(changedOriginAndForward, 429, errors.rateLimited);
  assertNoCors(changedOriginAndForward);

  const absentResult = {
    ...flow.resultSubmission,
    transactionId: UNKNOWN_ID,
  };
  assertJsonResponse(await submitResult(floods, absentResult), 404, errors.notFound);
  assertJsonResponse(await submitResult(floods, absentResult), 429, errors.rateLimited);

  const absentCancel = {
    codeVerifier: flow.redeemSubmission.codeVerifier,
    schemaVersion: 1,
    state: flow.registration.state,
    transactionId: UNKNOWN_ID,
  };
  const cancelPath = `/relay/v1/transactions/${UNKNOWN_ID}/cancel`;
  assertJsonResponse(await request(floods.baseUrl, {
    method: 'POST',
    pathname: cancelPath,
    origin: flow.origin,
    body: jsonBody(absentCancel),
  }), 404, errors.notFound);
  assertJsonResponse(await request(floods.baseUrl, {
    method: 'POST',
    pathname: cancelPath,
    origin: OTHER_REGISTERED_ORIGIN,
    body: jsonBody(absentCancel),
  }), 429, errors.rateLimited);

  const absentRedeem = {
    ...flow.redeemSubmission,
    code: 'd'.repeat(64),
    transactionId: UNKNOWN_ID,
  };
  assertJsonResponse(await redeem(floods, absentRedeem), 404, errors.notFound);
  assertJsonResponse(await redeem(floods, absentRedeem, OTHER_REGISTERED_ORIGIN), 429, errors.rateLimited);
});

test('partitions known GET polling by server-owned client binding while random IDs share one peer bucket', async (t) => {
  let now = FIXED_NOW;
  const harness = await startHarness({
    now: () => now,
    rateLimit: {
      bindingMaxRequests: 1,
      coarseMaxRequests: 10,
      maxRequests: 1,
      windowMs: 30_000,
    },
  });
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  now += 30_001;
  const otherRegistration = makeRegistration({
    clientId: 'spaceaware-web-v1',
    operation: 'sdn.wallet.account.v1',
    state: '7'.repeat(64),
    transactionId: '6'.repeat(64),
  });
  assert.equal((await register(harness, otherRegistration, OTHER_REGISTERED_ORIGIN)).status, 201);

  const firstPath = `/relay/v1/transactions/${flow.registration.transactionId}`;
  const otherPath = `/relay/v1/transactions/${otherRegistration.transactionId}`;
  const firstRead = await request(harness.baseUrl, { pathname: firstPath, origin: OTHER_REGISTERED_ORIGIN });
  const otherRead = await request(harness.baseUrl, { pathname: otherPath, origin: flow.origin });
  assert.equal(firstRead.status, 200);
  assert.equal(otherRead.status, 200);
  assertNoCors(firstRead);
  assertNoCors(otherRead);
  assertJsonResponse(await request(harness.baseUrl, { pathname: firstPath }), 429, errors.rateLimited);
  assertJsonResponse(await request(harness.baseUrl, { pathname: otherPath }), 429, errors.rateLimited);

  const firstAbsent = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${UNKNOWN_ID}`,
  });
  assertJsonResponse(firstAbsent, 404, errors.notFound);
  assertNoCors(firstAbsent);
  const secondAbsent = await request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${'e'.repeat(64)}`,
  });
  assertJsonResponse(secondAbsent, 429, errors.rateLimited);
  assertNoCors(secondAbsent);
});

test('a coarse GET rejection performs no SQLite SELECT before returning 429', async (t) => {
  let selects = 0;
  const harness = await startHarness({
    rateLimit: {
      bindingMaxRequests: 10,
      coarseMaxRequests: 1,
      maxRequests: 1,
      windowMs: 30_000,
    },
    testHooks: {
      observeSelect() {
        selects += 1;
      },
    },
  });
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  selects = 0;
  const pathname = `/relay/v1/transactions/${flow.registration.transactionId}`;
  assert.equal((await request(harness.baseUrl, { pathname })).status, 200);
  assert.ok(selects > 0);
  const afterFirstRead = selects;
  assertJsonResponse(await request(harness.baseUrl, { pathname }), 429, errors.rateLimited);
  assert.equal(selects, afterFirstRead);
});

test('rate windows use the injected monotonic clock instead of rolled wall time', async (t) => {
  let wallNow = FIXED_NOW;
  let monotonicNow = 10_000;
  const harness = await startHarness({
    monotonicNow: () => monotonicNow,
    now: () => wallNow,
    rateLimit: {
      bindingMaxRequests: 10,
      coarseMaxRequests: 1,
      maxRequests: 1,
      windowMs: 30_000,
    },
  });
  t.after(() => harness.close());
  const probe = () => request(harness.baseUrl, {
    method: 'POST',
    rawPath: '/relay/v1/transactions?monotonic-probe=1',
  });
  assertJsonResponse(await probe(), 404, errors.notFound);
  wallNow += 60_000;
  assertJsonResponse(await probe(), 429, errors.rateLimited);
  monotonicNow += 30_001;
  wallNow -= 120_000;
  assertJsonResponse(await probe(), 404, errors.notFound);
});

test('trusts one strict X-Real-IP only across the explicit loopback-proxy boundary', async (t) => {
  const rateLimit = {
    bindingMaxRequests: 10,
    coarseMaxRequests: 1,
    maxRequests: 1,
    windowMs: 30_000,
  };
  const probe = (harness, xRealIp) => request(harness.baseUrl, {
    method: 'POST',
    rawPath: '/relay/v1/transactions?proxy-probe=1',
    headers: { 'X-Real-IP': xRealIp },
  });

  const untrusted = await startHarness({ rateLimit });
  t.after(() => untrusted.close());
  assertJsonResponse(await probe(untrusted, '198.51.100.1'), 404, errors.notFound);
  assertJsonResponse(await probe(untrusted, '203.0.113.9'), 429, errors.rateLimited);

  const trusted = await startHarness({ rateLimit, trustLoopbackProxy: true });
  t.after(() => trusted.close());
  assertJsonResponse(await probe(trusted, '198.51.100.1'), 404, errors.notFound);
  assertJsonResponse(await probe(trusted, '203.0.113.9'), 404, errors.notFound);
  assertJsonResponse(await probe(trusted, '198.51.100.1'), 429, errors.rateLimited);

  const malformed = await startHarness({ rateLimit, trustLoopbackProxy: true });
  t.after(() => malformed.close());
  assertJsonResponse(await probe(malformed, '198.51.100.1, 203.0.113.9'), 404, errors.notFound);
  assertJsonResponse(await probe(malformed, 'not-an-ip'), 429, errors.rateLimited);

  const nonLoopback = await startHarness({
    rateLimit,
    trustLoopbackProxy: true,
    testHooks: {
      directPeerAddress() {
        return '10.0.0.8';
      },
    },
  });
  t.after(() => nonLoopback.close());
  assertJsonResponse(await probe(nonLoopback, '198.51.100.1'), 404, errors.notFound);
  assertJsonResponse(await probe(nonLoopback, '203.0.113.9'), 429, errors.rateLimited);
});

test('partitions every registered mutation binding by the trusted server-owned peer', async (t) => {
  const harness = await startHarness({
    rateLimit: {
      bindingMaxRequests: 1,
      coarseMaxRequests: 100,
      windowMs: 30_000,
    },
    trustLoopbackProxy: true,
  });
  t.after(() => harness.close());
  let nextByte = 0xc0;
  const nextRegistration = () => {
    const transactionByte = nextByte.toString(16).padStart(2, '0');
    nextByte += 1;
    const stateByte = nextByte.toString(16).padStart(2, '0');
    nextByte += 1;
    return makeRegistration({
      state: stateByte.repeat(32),
      transactionId: transactionByte.repeat(32),
    });
  };
  const from = (address) => ({ 'X-Real-IP': address });
  const registerFrom = (registration, address) => request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: flow.origin,
    body: jsonBody(registration),
    headers: from(address),
  });
  const fetchFrom = (registration, address) => request(harness.baseUrl, {
    pathname: `/relay/v1/transactions/${registration.transactionId}`,
    headers: from(address),
  });
  const resultFrom = (registration, resultToken, address) => request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${registration.transactionId}/result`,
    body: jsonBody({
      result: flow.resultSubmission.result,
      resultToken,
      schemaVersion: 1,
      transactionId: registration.transactionId,
    }),
    headers: from(address),
  });
  const cancelFrom = (registration, address) => request(harness.baseUrl, {
    method: 'POST',
    pathname: `/relay/v1/transactions/${registration.transactionId}/cancel`,
    origin: flow.origin,
    body: jsonBody({
      codeVerifier: flow.redeemSubmission.codeVerifier,
      schemaVersion: 1,
      state: registration.state,
      transactionId: registration.transactionId,
    }),
    headers: from(address),
  });
  const redeemFrom = (registration, code, address) => request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/codes/redeem',
    origin: flow.origin,
    body: jsonBody({
      code,
      codeVerifier: flow.redeemSubmission.codeVerifier,
      schemaVersion: 1,
      state: registration.state,
      transactionId: registration.transactionId,
    }),
    headers: from(address),
  });

  const firstRegistration = nextRegistration();
  const samePeerRegistration = nextRegistration();
  const otherPeerRegistration = nextRegistration();
  assert.equal((await registerFrom(firstRegistration, '198.51.100.1')).status, 201);
  assertJsonResponse(
    await registerFrom(samePeerRegistration, '198.51.100.1'),
    429,
    errors.rateLimited,
  );
  assert.equal((await registerFrom(otherPeerRegistration, '198.51.100.2')).status, 201);

  const resultRegistrations = [nextRegistration(), nextRegistration(), nextRegistration()];
  const resultTokens = [];
  for (const [index, registration] of resultRegistrations.entries()) {
    const address = `198.51.100.${10 + index}`;
    assert.equal((await registerFrom(registration, address)).status, 201);
    const fetched = await fetchFrom(registration, address);
    assert.equal(fetched.status, 200);
    resultTokens.push(fetched.json.resultToken);
  }
  assert.equal((await resultFrom(resultRegistrations[0], resultTokens[0], '198.51.100.20')).status, 201);
  assertJsonResponse(
    await resultFrom(resultRegistrations[1], resultTokens[1], '198.51.100.20'),
    429,
    errors.rateLimited,
  );
  assert.equal((await resultFrom(
    resultRegistrations[2],
    resultTokens[2],
    '198.51.100.21',
  )).status, 201);

  const cancelRegistrations = [nextRegistration(), nextRegistration(), nextRegistration()];
  for (const [index, registration] of cancelRegistrations.entries()) {
    assert.equal((await registerFrom(registration, `198.51.100.${30 + index}`)).status, 201);
  }
  assert.equal((await cancelFrom(cancelRegistrations[0], '198.51.100.40')).status, 204);
  assertJsonResponse(
    await cancelFrom(cancelRegistrations[1], '198.51.100.40'),
    429,
    errors.rateLimited,
  );
  assert.equal((await cancelFrom(cancelRegistrations[2], '198.51.100.41')).status, 204);

  const redeemRegistrations = [nextRegistration(), nextRegistration(), nextRegistration()];
  const authorizationCodes = [];
  for (const [index, registration] of redeemRegistrations.entries()) {
    const registrationAddress = `198.51.100.${50 + index}`;
    assert.equal((await registerFrom(registration, registrationAddress)).status, 201);
    const fetched = await fetchFrom(registration, registrationAddress);
    assert.equal(fetched.status, 200);
    const completed = await resultFrom(
      registration,
      fetched.json.resultToken,
      `198.51.100.${60 + index}`,
    );
    assert.equal(completed.status, 201);
    authorizationCodes.push(
      new URLSearchParams(new URL(completed.json.redirectUri).hash.slice(1)).get('code'),
    );
  }
  assert.equal((await redeemFrom(
    redeemRegistrations[0],
    authorizationCodes[0],
    '198.51.100.70',
  )).status, 200);
  assertJsonResponse(
    await redeemFrom(redeemRegistrations[1], authorizationCodes[1], '198.51.100.70'),
    429,
    errors.rateLimited,
  );
  assert.equal((await redeemFrom(
    redeemRegistrations[2],
    authorizationCodes[2],
    '198.51.100.71',
  )).status, 200);
});

test('hard-bounds monotonic rate buckets and reclaims them only after the window', async (t) => {
  let monotonicNow = 10_000;
  const harness = await startHarness({
    monotonicNow: () => monotonicNow,
    rateLimit: {
      bindingMaxRequests: 10,
      coarseMaxRequests: 10,
      maxBuckets: 16,
      windowMs: 30_000,
    },
    trustLoopbackProxy: true,
  });
  t.after(() => harness.close());
  const probe = (address) => request(harness.baseUrl, {
    method: 'POST',
    rawPath: '/relay/v1/transactions?bucket-probe=1',
    headers: { 'X-Real-IP': address },
  });

  for (let index = 1; index <= 16; index += 1) {
    assertJsonResponse(await probe(`198.51.100.${index}`), 404, errors.notFound);
  }
  assertJsonResponse(await probe('203.0.113.1'), 429, errors.rateLimited);

  monotonicNow += 30_001;
  assertJsonResponse(await probe('203.0.113.1'), 404, errors.notFound);
});

test('hard-bounds rows, preserves IDs until expiry, then reclaims terminal tombstones for new IDs', async (t) => {
  let now = FIXED_NOW;
  const harness = await startHarness({ maxRows: 1, now: () => now });
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);
  assertJsonResponse(await register(harness), 409, errors.conflict);
  const second = makeRegistration({ transactionId: '3'.repeat(64), state: '4'.repeat(64) });
  assertJsonResponse(await register(harness, second), 429, errors.rateLimited);
  now += 300_001;
  assert.equal((await register(harness, second)).status, 201);

  const database = new Database(harness.databasePath, { readonly: true });
  const columns = database.prepare('PRAGMA table_info(relay_transactions)').all().map(({ name }) => name);
  const rows = database.prepare('SELECT transaction_id FROM relay_transactions ORDER BY transaction_id').all();
  database.close();
  assert.deepEqual(rows, [{ transaction_id: second.transactionId }]);
  const columnText = columns.join(' ').toLowerCase();
  for (const forbidden of ['password', 'seed', 'mnemonic', 'private', 'webauthn', 'credential']) {
    assert.ok(!columnText.includes(forbidden), `schema must not store ${forbidden}`);
  }
});

test('OPTIONS exists only on cross-origin POST routes, echoes only registered origins, and never enables credentials', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  assert.equal((await register(harness)).status, 201);

  for (const pathname of [
    '/relay/v1/transactions',
    `/relay/v1/transactions/${flow.registration.transactionId}/result`,
    `/relay/v1/transactions/${flow.registration.transactionId}/cancel`,
    '/relay/v1/codes/redeem',
  ]) {
    const response = await request(harness.baseUrl, {
      method: 'OPTIONS',
      pathname,
      origin: flow.origin,
      headers: { 'Access-Control-Request-Method': 'POST' },
    });
    assert.equal(response.status, 204);
    assert.equal(response.raw.length, 0);
    assertCors(response, flow.origin);
  }

  const unregistered = await request(harness.baseUrl, {
    method: 'OPTIONS',
    pathname: '/relay/v1/codes/redeem',
    origin: 'https://attacker.invalid',
    headers: { 'Access-Control-Request-Method': 'POST' },
  });
  assertJsonResponse(unregistered, 403, errors.unregistered);
  assertNoCors(unregistered);

  for (const pathname of [
    '/healthz',
    `/relay/v1/transactions/${flow.registration.transactionId}`,
  ]) {
    assertJsonResponse(await request(harness.baseUrl, {
      method: 'OPTIONS',
      pathname,
      origin: flow.origin,
    }), 404, errors.notFound);
  }
});

test('bounds error responses and never echoes hostile public input', async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());
  const secretMarker = 'DO-NOT-ECHO-THIS-PUBLIC-INPUT';
  const body = Buffer.from(`{"${secretMarker}":"${'x'.repeat(4096)}"}`, 'utf8');
  const response = await request(harness.baseUrl, {
    method: 'POST',
    pathname: '/relay/v1/transactions',
    origin: flow.origin,
    body,
  });
  assertJsonResponse(response, 400, errors.malformed);
  assert.ok(response.raw.length < 256);
  assert.ok(!response.text.includes(secretMarker));
});
