import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const walletUiDirectory = fileURLToPath(new URL('../../', import.meta.url));
const WALLET_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'";
const WALLET_PERMISSIONS = 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)';
const WALLET_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-security-policy': WALLET_CSP,
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': WALLET_PERMISSIONS,
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});
const FIXTURE_CONTROL_ORIGIN = 'http://127.0.0.1:18776';
const FROZEN_PAGE_ORIGINS = new Set([
  'https://spacedatanetwork.org',
  'https://static.spacedatanetwork.org',
  'https://wallet.spacedatanetwork.org',
]);
const FIXTURE_CONTROL_PATHS = new Set([
  '/healthz',
  '/__fixture/complete',
  '/__fixture/reset',
  '/__fixture/snapshot',
  '/__fixture/tamper',
]);

function fixtureControlUrl(path) {
  if (!FIXTURE_CONTROL_PATHS.has(path)) throw new Error('unregistered fixture control path');
  return new URL(path, FIXTURE_CONTROL_ORIGIN).href;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function resetFixture() {
  const response = await fetch(fixtureControlUrl('/__fixture/reset'), { method: 'POST' });
  expect(response.status).toBe(204);
}

async function fixtureSnapshot() {
  const response = await fetch(fixtureControlUrl('/__fixture/snapshot'));
  expect(response.status).toBe(200);
  return response.json();
}

async function setTamper(mode) {
  const response = await fetch(fixtureControlUrl('/__fixture/tamper'), {
    body: JSON.stringify({ mode }),
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
  });
  expect(response.status).toBe(204);
}

async function openRegisteredPopup(context, page) {
  const registrationPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/transactions');
  const popupPromise = context.waitForEvent('page');
  await page.locator('[data-wallet-presenter] button').first().click();
  const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
  return { popup, registration: registration.postDataJSON() };
}

test.beforeEach(async () => {
  await resetFixture();
});

test.afterEach(async ({}, testInfo) => {
  const snapshot = await fixtureSnapshot();
  if (testInfo.title === 'serves only exact wallet release bytes with the frozen security policy') {
    expect(snapshot.unexpected).toEqual([
      {
        host: 'wallet.spacedatanetwork.org',
        method: 'GET',
        scope: 'wallet',
        url: '/assets/wallet-origin.js',
      },
      {
        host: 'static.spacedatanetwork.org',
        method: 'GET',
        scope: 'consumer',
        url: '/assets/not-hashed.js',
      },
    ]);
    return;
  }
  if (testInfo.title === 'maps only the frozen production hosts through real TLS origins') {
    expect(snapshot.unexpected.length).toBeGreaterThan(0);
    expect(snapshot.unexpected.every((entry) => (
      entry.host === 'unregistered.invalid:443'
        && entry.method === 'CONNECT'
        && entry.scope === 'proxy'
        && entry.url === 'unregistered.invalid:443'
    ))).toBe(true);
    return;
  }
  expect(snapshot.unexpected).toEqual([]);
});

test('runs against the isolated local TLS fixture', async () => {
  const response = await fetch(fixtureControlUrl('/healthz'));
  expect(response.status).toBe(200);
  expect(await response.text()).toBe('ok\n');
});

test('maps only the frozen production hosts through real TLS origins', async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const consumer = await context.newPage();
  const consumerResponse = await consumer.goto('https://spacedatanetwork.org/harness');
  expect(consumerResponse?.status()).toBe(200);
  expect(consumer.url()).toBe('https://spacedatanetwork.org/harness');
  await expect(consumer.locator('[data-public-content]')).toHaveText('Public models remain available');

  const wallet = await context.newPage();
  const walletResponse = await wallet.goto('https://wallet.spacedatanetwork.org/');
  expect(walletResponse?.status()).toBe(200);
  expect(wallet.url()).toBe('https://wallet.spacedatanetwork.org/');

  const unknown = await context.newPage();
  await expect(unknown.goto('https://unregistered.invalid/')).rejects.toThrow(/TUNNEL|tunnel/u);
  await context.close();
});

test('serves only exact wallet release bytes with the frozen security policy', async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const transactionRoute = `https://wallet.spacedatanetwork.org/transaction/${'0'.repeat(64)}`;
  const documentResponse = await page.goto(transactionRoute);
  expect(documentResponse?.status()).toBe(200);
  const documentHeaders = documentResponse?.headers() ?? {};
  for (const [name, value] of Object.entries(WALLET_HEADERS)) {
    expect(documentHeaders[name], name).toBe(value);
  }
  expect(documentHeaders['content-type']).toBe('text/html; charset=utf-8');

  const expectedIntegrity = await readFile(`${walletUiDirectory}dist/wallet-origin-host/integrity.json`);
  const expectedIntegrityValue = JSON.parse(expectedIntegrity.toString('utf8'));
  const wasmIntegrityPath = Object.keys(expectedIntegrityValue.files)
    .find((path) => /^assets\/wallet-origin\.[0-9a-f]{64}\.wasm$/u.test(path));
  expect(wasmIntegrityPath).toBeTruthy();
  const paths = await page.evaluate(() => ({
    css: document.querySelector('link[rel="stylesheet"]')?.getAttribute('href'),
    js: document.querySelector('script[type="module"]')?.getAttribute('src'),
  }));
  paths.wasm = `/${wasmIntegrityPath}`;
  for (const [kind, path] of Object.entries(paths)) {
    expect(path, `${kind} path`).toMatch(/^\/assets\/wallet-origin\.[0-9a-f]{64}\.(?:css|js|wasm)$/u);
    const expectedBytes = await readFile(`${walletUiDirectory}dist/wallet-origin-host${path}`);
    const response = await context.request.get(new URL(path, transactionRoute).href);
    expect(response.status(), `${kind} status`).toBe(200);
    const bytes = await response.body();
    expect(Buffer.compare(bytes, expectedBytes), `${kind} bytes`).toBe(0);
    expect(path, `${kind} content hash`).toContain(sha256(bytes));
    expect(response.headers()['cache-control'], `${kind} cache`).toBe('public, max-age=31536000, immutable');
    expect(response.headers()['cross-origin-resource-policy'], `${kind} CORP`).toBe('same-origin');
    expect(response.headers()['x-content-type-options'], `${kind} nosniff`).toBe('nosniff');
    expect(response.headers()['content-type'], `${kind} MIME`).toBe({
      css: 'text/css; charset=utf-8',
      js: 'text/javascript; charset=utf-8',
      wasm: 'application/wasm',
    }[kind]);
  }

  const integrityResponse = await context.request.get('https://wallet.spacedatanetwork.org/integrity.json');
  expect(integrityResponse.status()).toBe(200);
  expect(Buffer.compare(await integrityResponse.body(), expectedIntegrity)).toBe(0);
  expect(integrityResponse.headers()['content-type']).toBe('application/json; charset=utf-8');
  expect(integrityResponse.headers()['cache-control']).toBe('no-store');

  expect((await context.request.get('https://wallet.spacedatanetwork.org/assets/wallet-origin.js')).status()).toBe(404);
  expect((await context.request.get('https://static.spacedatanetwork.org/assets/not-hashed.js')).status()).toBe(404);
  await context.close();
});

test('fails closed when any public or wallet-origin release artifact is tampered', async ({ browser }) => {
  test.setTimeout(60_000);
  const publicCases = [
    { mode: 'public-js', pathPattern: /\/sdn-wallet-public-client\.[0-9a-f]{64}\.js$/u },
    { mode: 'public-css', pathPattern: /\/sdn-wallet-public-client\.[0-9a-f]{64}\.css$/u },
  ];
  for (const { mode, pathPattern } of publicCases) {
    await resetFixture();
    await setTamper(mode);
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const consoleMessages = [];
    const pageRequests = [];
    page.on('console', (message) => consoleMessages.push(message.text()));
    page.on('request', (request) => pageRequests.push(request.url()));
    const response = await page.goto('https://spacedatanetwork.org/harness');
    expect(response?.status()).toBe(200);
    await expect(page.locator('[data-public-content]')).toHaveText('Public models remain available');

    let tamperedRequest;
    await expect.poll(async () => {
      const snapshot = await fixtureSnapshot();
      tamperedRequest = snapshot.requests.find((entry) => entry.tampered === mode);
      return tamperedRequest?.url;
    }).toMatch(pathPattern);
    await expect.poll(() => consoleMessages.some((text) => (
      text.startsWith("Failed to find a valid digest in the 'integrity' attribute for resource")
        && text.includes(tamperedRequest.url)
        && text.endsWith('The resource has been blocked.')
    ))).toBe(true);

    if (mode === 'public-js') {
      expect(await page.evaluate(() => typeof globalThis.SDNWalletPublicClient)).toBe('undefined');
    } else {
      expect(await page.evaluate(() => document.querySelector('[data-public-client-style]').sheet)).toBeNull();
      expect(await page.evaluate(() => typeof globalThis.SDNWalletPublicClient)).toBe('object');
    }
    await expect(page.locator('[data-wallet-presenter] button')).toHaveCount(2);
    const snapshot = await fixtureSnapshot();
    expect(snapshot.requests.some(({ host }) => host === 'wallet.spacedatanetwork.org')).toBe(false);
    expect(pageRequests.every((url) => FROZEN_PAGE_ORIGINS.has(new URL(url).origin))).toBe(true);
    await context.close();
  }

  for (const mode of ['origin-js', 'origin-css', 'origin-wasm']) {
    await resetFixture();
    await setTamper(mode);
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const consumer = await context.newPage();
    const consoleMessages = [];
    const pageRequests = [];
    context.on('request', (request) => pageRequests.push(request.url()));
    context.on('page', (page) => {
      page.on('console', (message) => consoleMessages.push(message.text()));
    });
    await consumer.goto('https://spacedatanetwork.org/harness');
    const { popup } = await openRegisteredPopup(context, consumer);
    expect(await popup.evaluate(() => window.opener === null)).toBe(true);

    let tamperedRequest;
    await expect.poll(async () => {
      const snapshot = await fixtureSnapshot();
      tamperedRequest = snapshot.requests.find((entry) => entry.tampered === mode);
      return tamperedRequest?.url;
    }).toMatch(new RegExp(`/assets/wallet-origin\\.[0-9a-f]{64}\\.${mode.slice(7)}$`, 'u'));
    await expect.poll(() => consoleMessages.some((text) => (
      text.startsWith("Failed to find a valid digest in the 'integrity' attribute for resource")
        && text.includes(tamperedRequest.url)
        && text.endsWith('The resource has been blocked.')
    ))).toBe(true);

    await expect(consumer.locator('[data-public-content]')).toHaveText('Public models remain available');
    await expect(popup.locator('input, textarea')).toHaveCount(0);
    if (mode === 'origin-js') {
      await expect(popup.locator('[data-wallet-origin-root]')).toBeEmpty();
      const snapshot = await fixtureSnapshot();
      expect(snapshot.requests.some(({ url }) => url.endsWith('.wasm'))).toBe(false);
    } else {
      await expect(popup.locator('.wallet-error')).toHaveText(
        'The wallet could not start. Close this window and try again.',
      );
    }
    expect(await popup.locator('html').evaluate((element) => element.outerHTML)).not.toMatch(
      /Username|Password|mnemonic|privateKey|seedHex/u,
    );
    await popup.close();
    await consumer.evaluate(() => globalThis.__walletTest.client.destroy());
    expect(pageRequests.every((url) => FROZEN_PAGE_ORIGINS.has(new URL(url).origin))).toBe(true);
    await context.close();
  }
});

test('loads the exact public IIFE and two presenters without activating the wallet', async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const requests = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.goto('https://spacedatanetwork.org/harness');

  const boundary = await page.evaluate(() => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'SDNWalletPublicClient');
    return {
      configurable: descriptor?.configurable,
      enumerable: descriptor?.enumerable,
      frozen: Object.isFrozen(descriptor?.value),
      keys: descriptor ? Object.keys(descriptor.value) : [],
      startup: globalThis.__walletTest?.startup,
      writable: descriptor?.writable,
    };
  });
  expect(boundary).toEqual({
    configurable: false,
    enumerable: false,
    frozen: true,
    keys: ['create'],
    startup: {
      eventListeners: [],
      opens: 0,
      storageCalls: [],
      walletFetches: 0,
    },
    writable: false,
  });
  await expect(page.locator('[data-wallet-presenter]')).toHaveCount(2);
  await expect(page.locator('[data-wallet-presenter] button')).toHaveText(['Login', 'Login']);
  expect(requests.filter((url) => url.startsWith('https://wallet.spacedatanetwork.org/'))).toEqual([]);

  const resources = await page.evaluate(() => ({
    publicScript: Object.fromEntries([...document.querySelector('[data-public-client-script]').attributes]
      .map(({ name, value }) => [name, value])),
    publicStyle: Object.fromEntries([...document.querySelector('[data-public-client-style]').attributes]
      .map(({ name, value }) => [name, value])),
  }));
  const { version } = JSON.parse(
    await readFile(`${walletUiDirectory}package.json`, 'utf8'),
  );
  const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const immutablePublicAssetUrl = new RegExp(
    `^https://static\\.spacedatanetwork\\.org/assets/hd-wallet-ui/${escapedVersion}/[a-z-]+\\.[0-9a-f]{64}\\.(?:css|js)$`,
    'u',
  );
  for (const [kind, resource] of Object.entries(resources)) {
    const url = resource.src ?? resource.href;
    expect(url, kind).toMatch(immutablePublicAssetUrl);
    expect(resource.integrity, `${kind} SRI`).toMatch(/^sha384-[A-Za-z0-9+/]+={0,2}$/u);
    expect(resource.crossorigin, `${kind} crossorigin`).toBe('anonymous');
    const response = await context.request.get(url);
    expect(response.status()).toBe(200);
    expect(response.headers()['access-control-allow-origin']).toBe('*');
    expect(response.headers()['cross-origin-resource-policy']).toBe('cross-origin');
    expect(response.headers()['cache-control']).toBe('public, max-age=31536000, immutable');
    expect(response.headers()['x-content-type-options']).toBe('nosniff');
    expect(response.headers()['content-type']).toBe(kind === 'publicScript'
      ? 'text/javascript; charset=utf-8'
      : 'text/css; charset=utf-8');
  }
  await context.close();
});

test('keeps trusted-click popup order synchronous through real connect and Account logout', async ({ browser }) => {
  test.setTimeout(60_000);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const consoleMessages = [];
  const failedResponses = [];
  const pageErrors = [];
  const pageRequests = [];
  const requestBodies = [];
  const consumerRequests = [];
  const observePage = (contextPage) => {
    contextPage.on('console', (message) => consoleMessages.push({
      location: message.location(),
      text: message.text(),
      type: message.type(),
      url: contextPage.url(),
    }));
    contextPage.on('pageerror', (error) => pageErrors.push({ message: error.message, url: contextPage.url() }));
  };
  observePage(page);
  context.on('page', observePage);
  context.on('response', (response) => {
    if (response.status() >= 400) failedResponses.push({ status: response.status(), url: response.url() });
  });
  page.on('request', (request) => consumerRequests.push({
    headers: request.headers(),
    postData: request.postData(),
    url: request.url(),
  }));
  context.on('request', (request) => {
    pageRequests.push(request.url());
    if (request.postData()) requestBodies.push(request.postData());
  });
  await page.goto('https://spacedatanetwork.org/harness');

  const registrationPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/transactions');
  const popupPromise = context.waitForEvent('page');
  await page.locator('[data-wallet-presenter] button').first().click();
  const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
  const registrationBody = registration.postDataJSON();
  expect(registrationBody.operation).toBe('sdn.wallet.connect.v1');
  expect(registrationBody.clientId).toBe('sdn-landing-web-v1');
  expect(registrationBody.transactionId).toMatch(/^[0-9a-f]{64}$/u);
  expect(registrationBody.state).toMatch(/^[0-9a-f]{64}$/u);
  await expect.poll(() => popup.url()).toBe(
    `https://wallet.spacedatanetwork.org/transaction/${registrationBody.transactionId}`,
  );
  expect(await popup.evaluate(() => window.opener === null)).toBe(true);

  const ordered = await page.evaluate(() => globalThis.__walletTest.events);
  expect(ordered.map(({ kind }) => kind)).toEqual([
    'trusted-click',
    'connect-enter',
    'popup-open',
    'popup-return',
    'connect-return',
    'handler-return',
  ]);
  expect(ordered[2]).toMatchObject({
    args: [
      `https://wallet.spacedatanetwork.org/transaction/${registrationBody.transactionId}`,
      '_blank',
      'noopener',
    ],
    sync: true,
  });
  expect(ordered[3].returnedNull).toBe(true);
  expect(await page.evaluate(() => globalThis.__walletTest.startup.eventListeners)).toEqual(['storage']);

  await expect(popup.getByLabel('Username')).toBeVisible({ timeout: 20_000 });
  await expect(popup.getByLabel('Password')).toBeVisible();
  await popup.getByLabel('Username').fill('  ALICE_01  ');
  await popup.getByLabel('Password').fill('Correct Horse Battery Staple!');
  await popup.getByRole('button', { exact: true, name: 'Login' }).click();
  await expect(popup.getByLabel('Password')).toHaveCount(0, { timeout: 20_000 });
  await expect(popup.getByRole('heading', { name: 'Confirm wallet action' })).toBeVisible({ timeout: 20_000 });
  const publishedConnect = popup.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `https://wallet.spacedatanetwork.org/relay/v1/transactions/${registrationBody.transactionId}/result`);
  const redeemEvent = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/codes/redeem');
  await popup.getByRole('button', { exact: true, name: 'Confirm' }).click();
  const connectPublication = await publishedConnect;
  await redeemEvent;
  expect(connectPublication.postDataJSON()).toMatchObject({
    resultToken: 'R'.repeat(43),
    schemaVersion: 1,
    transactionId: registrationBody.transactionId,
  });
  await expect(page.locator('[data-wallet-presenter] button')).toHaveText(['Account', 'Account']);

  const accountRegistrationPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/transactions'
    && request.postDataJSON()?.operation === 'sdn.wallet.account.v1');
  const accountPopupPromise = context.waitForEvent('page');
  await page.locator('[data-wallet-presenter] button').nth(1).click();
  const [accountRegistration, accountPopup] = await Promise.all([
    accountRegistrationPromise,
    accountPopupPromise,
  ]);
  const accountBody = accountRegistration.postDataJSON();
  await expect(accountPopup.getByLabel('Username')).toBeVisible({ timeout: 20_000 });
  await accountPopup.getByLabel('Username').fill('  ALICE_01  ');
  await accountPopup.getByLabel('Password').fill('Correct Horse Battery Staple!');
  await accountPopup.getByRole('button', { exact: true, name: 'Login' }).click();
  await expect(accountPopup.getByRole('heading', { name: 'Confirm wallet action' })).toBeVisible({ timeout: 20_000 });
  await accountPopup.getByRole('button', { exact: true, name: 'Confirm' }).click();
  await expect(accountPopup.getByRole('heading', { exact: true, name: 'Account' })).toBeVisible({ timeout: 20_000 });
  const accountPublication = accountPopup.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `https://wallet.spacedatanetwork.org/relay/v1/transactions/${accountBody.transactionId}/result`);
  const redeemLogout = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/codes/redeem'
    && request.postDataJSON()?.transactionId === accountBody.transactionId);
  await accountPopup.getByRole('button', { exact: true, name: 'Logout' }).click();
  expect((await accountPublication).postDataJSON().result).toEqual({
    connectionExpiresAt: null,
    event: 'disconnected',
    identity: null,
    schemaVersion: 1,
  });
  await redeemLogout;
  await expect(page.locator('[data-wallet-presenter] button')).toHaveText(['Login', 'Login']);

  const consumerEvidence = await page.evaluate(() => ({
    controls: [...document.querySelectorAll('input, textarea')].map((control) => ({
      attributes: [...control.attributes].map(({ name, value }) => [name, value]),
      defaultValue: control.defaultValue,
      value: control.value,
    })),
    events: globalThis.__walletTest.events,
    html: document.documentElement.outerHTML,
    storage: Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]),
  }));
  const allObservable = JSON.stringify({ consoleMessages, consumerEvidence, requestBodies });
  const consumerObservable = JSON.stringify({ consumerEvidence, consumerRequests });
  for (const secret of [
    'Correct Horse Battery Staple!',
    '  ALICE_01  ',
    '436f727265637420486f727365204261747465727920537461706c6521',
    'Q29ycmVjdCBIb3JzZSBCYXR0ZXJ5IFN0YXBsZSE',
  ]) {
    expect(allObservable).not.toContain(secret);
  }
  expect(allObservable).not.toMatch(/mnemonic|passwordBase64url|privateKey|seedHex|seedBase64url/u);
  expect(consumerObservable).not.toContain('ALICE_01');
  expect(consumerObservable).not.toContain('alice_01');
  expect(consumerObservable).not.toContain('.wasm');
  expect(consumerObservable).not.toContain('\0asm');
  expect(consumerObservable).not.toContain('\\0asm');
  expect(consumerObservable).not.toContain('\\u0000asm');
  expect(consumerObservable).not.toContain('AGFzbQEAAAAB');
  expect(consumerEvidence.storage).toEqual([]);
  expect(pageRequests.every((url) => FROZEN_PAGE_ORIGINS.has(new URL(url).origin))).toBe(true);
  expect(pageErrors).toEqual([]);
  expect(failedResponses.every(({ status, url }) => (
    status === 404 && url === 'https://wallet.spacedatanetwork.org/favicon.ico'
  ))).toBe(true);
  const unexpectedConsole = consoleMessages.filter(({ location, text, type }) => {
    const ignoredMetaFrameAncestors = type === 'error'
      && text === "The Content Security Policy directive 'frame-ancestors' is ignored when delivered via a <meta> element.";
    const expectedFaviconProbe = type === 'error'
      && text === 'Failed to load resource: the server responded with a status of 404 (Not Found)'
      && location.url === 'https://wallet.spacedatanetwork.org/favicon.ico';
    return !ignoredMetaFrameAncestors && !expectedFaviconProbe;
  });
  expect(unexpectedConsole).toEqual([]);
  await context.close();
});

test('redeems a same-document callback record through the polling fallback', async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const pageRequests = [];
  context.on('request', (request) => pageRequests.push(request.url()));
  const page = await context.newPage();
  await page.goto('https://spacedatanetwork.org/harness');
  const registrationPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/transactions');
  const popupPromise = context.waitForEvent('page');
  await page.locator('[data-wallet-presenter] button').first().click();
  const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
  const transactionId = registration.postDataJSON().transactionId;

  const completionResponse = await fetch(fixtureControlUrl('/__fixture/complete'), {
    body: JSON.stringify({ event: 'connected', transactionId }),
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
  });
  expect(completionResponse.status).toBe(200);
  const completion = await completionResponse.json();
  const redemption = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === 'https://wallet.spacedatanetwork.org/relay/v1/codes/redeem'
    && request.postDataJSON()?.transactionId === transactionId);
  await page.evaluate(({ code, state }) => {
    localStorage.setItem(`sdn.wallet.callback.v1:${state}`, JSON.stringify({
      code,
      expiresAt: new Date(Date.now() + 120_000).toISOString(),
      schemaVersion: 1,
      state,
    }));
  }, completion);
  await redemption;
  await expect(page.locator('[data-wallet-presenter] button')).toHaveText(['Account', 'Account']);
  const storageCalls = await page.evaluate(() => globalThis.__walletTest.startup.storageCalls);
  expect(storageCalls).toContain('setItem');
  expect(storageCalls).toContain('getItem');
  expect(storageCalls).toContain('removeItem');
  await page.evaluate(() => globalThis.__walletTest.client.disconnect());
  await expect(page.locator('[data-wallet-presenter] button')).toHaveText(['Login', 'Login']);
  expect(pageRequests.every((url) => FROZEN_PAGE_ORIGINS.has(new URL(url).origin))).toBe(true);
  await popup.close();
  await context.close();
});

test('refuses framing before wallet assets, WASM, or credential controls load', async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const transactionUrl = `https://wallet.spacedatanetwork.org/transaction/${'f'.repeat(64)}`;
  const transactionResponse = page.waitForResponse((response) => response.url() === transactionUrl);
  await page.goto('https://spacedatanetwork.org/frame-harness');
  expect((await transactionResponse).status()).toBe(200);
  await expect.poll(() => page.frames().some((frame) => frame.url() === transactionUrl)).toBe(false);
  await expect(page.locator('input, [data-wallet-origin-root]')).toHaveCount(0);
  const snapshot = await (await fetch(fixtureControlUrl('/__fixture/snapshot'))).json();
  expect(snapshot.requests.filter(({ host }) => host === 'wallet.spacedatanetwork.org'))
    .toEqual([{ host: 'wallet.spacedatanetwork.org', method: 'GET', scope: 'wallet', url: `/transaction/${'f'.repeat(64)}` }]);
  await context.close();
});
