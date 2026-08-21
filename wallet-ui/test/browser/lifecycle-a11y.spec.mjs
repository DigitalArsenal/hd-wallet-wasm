import { expect, test } from '@playwright/test';

const FIXTURE_CONTROL_ORIGIN = 'http://127.0.0.1:18776';
const FROZEN_PAGE_ORIGINS = new Set([
  'https://spacedatanetwork.org',
  'https://static.spacedatanetwork.org',
  'https://wallet.spacedatanetwork.org',
]);
const WALLET_ORIGIN = 'https://wallet.spacedatanetwork.org';

test.use({
  browserName: 'chromium',
  channel: 'chrome',
  headless: true,
  ignoreHTTPSErrors: true,
  proxy: { server: FIXTURE_CONTROL_ORIGIN },
  serviceWorkers: 'block',
});

function fixtureControlUrl(path) {
  if (!['/__fixture/reset', '/__fixture/snapshot'].includes(path)) {
    throw new Error('unregistered fixture control path');
  }
  return new URL(path, FIXTURE_CONTROL_ORIGIN).href;
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

async function openPendingWallet(context, consumer) {
  await consumer.goto('https://spacedatanetwork.org/harness');
  const registrationPromise = consumer.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions`);
  const popupPromise = context.waitForEvent('page');
  await consumer.locator('[data-wallet-presenter] button').first().click();
  const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
  const registrationBody = registration.postDataJSON();
  expect(registrationBody.transactionId).toMatch(/^[0-9a-f]{64}$/u);
  await expect.poll(() => popup.url()).toBe(
    `${WALLET_ORIGIN}/transaction/${registrationBody.transactionId}`,
  );
  await expect(popup.getByLabel('Username')).toBeVisible({ timeout: 20_000 });
  await expect(popup.getByLabel('Password')).toBeVisible();
  return { popup, registrationBody };
}

async function destroyConsumerAndExpectCancellation(consumer, registrationBody) {
  const cancellationPromise = consumer.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions/${registrationBody.transactionId}/cancel`);
  await consumer.evaluate(() => globalThis.__walletTest.client.destroy());
  const cancellation = await cancellationPromise;
  expect(cancellation.postDataJSON()).toEqual({
    codeVerifier: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
    schemaVersion: 1,
    state: registrationBody.state,
    transactionId: registrationBody.transactionId,
  });
  await expect.poll(async () => (await fixtureSnapshot()).transactions
    .some(({ transactionId }) => transactionId === registrationBody.transactionId)).toBe(false);
}

async function dispatchLifecycleAndCapture(popup, scenario) {
  return popup.evaluate(({ eventType, persisted, target }) => {
    const username = document.querySelector('input[name="username"]');
    const password = document.querySelector('input[name="password"]');
    const form = username?.form;
    if (!username || !password || !form) throw new Error('credential form unavailable');
    const makeEvent = () => {
      if (eventType === 'pageshow' || eventType === 'pagehide') {
        return new PageTransitionEvent(eventType, { persisted });
      }
      return new Event(eventType);
    };
    (target === 'document' ? document : window).dispatchEvent(makeEvent());
    const state = (control) => ({
      autocomplete: control.getAttribute('autocomplete'),
      defaultValue: control.defaultValue,
      disabled: control.disabled,
      inert: control.inert,
      name: control.getAttribute('name'),
      value: control.value,
    });
    return {
      bodyText: document.body.textContent,
      formConnected: form.isConnected,
      password: state(password),
      rootChildren: document.querySelector('[data-wallet-origin-root]')?.childElementCount ?? null,
      username: state(username),
    };
  }, scenario);
}

function expectClearedLifecycleState(state, secrets) {
  const clearedControl = {
    autocomplete: null,
    defaultValue: '',
    disabled: true,
    inert: true,
    name: null,
    value: '',
  };
  expect(state.username).toEqual(clearedControl);
  expect(state.password).toEqual(clearedControl);
  expect(state.formConnected).toBe(false);
  expect(state.rootChildren).toBe(0);
  for (const secret of secrets) expect(state.bodyText).not.toContain(secret);
}

async function assertNoUnexpectedApplicationRequests() {
  const snapshot = await fixtureSnapshot();
  expect(snapshot.unexpected).toEqual([]);
}

async function serviceWorkerState(page) {
  return page.evaluate(async () => {
    if (!('serviceWorker' in navigator)) {
      return { available: false, controlled: false, registrations: 0 };
    }
    const registrations = await navigator.serviceWorker.getRegistrations();
    return {
      available: true,
      controlled: navigator.serviceWorker.controller !== null,
      registrations: registrations.length,
    };
  });
}

test.beforeEach(async () => {
  await resetFixture();
});

const lifecycleScenarios = Object.freeze([
  Object.freeze({ eventType: 'pagehide', persisted: false, target: 'window' }),
  Object.freeze({ eventType: 'freeze', persisted: false, target: 'document' }),
  Object.freeze({ eventType: 'pageshow', persisted: true, target: 'window' }),
]);

for (const scenario of lifecycleScenarios) {
  test(`${scenario.eventType}${scenario.persisted ? ' from BFCache' : ''} clears credentials before consumer cancellation`, async ({ context, page }) => {
    test.setTimeout(45_000);
    const { popup, registrationBody } = await openPendingWallet(context, page);
    const usernameSecret = `lifecycle_${scenario.eventType}`;
    const passwordSecret = `Lifecycle ${scenario.eventType} Secret 934!`;
    await popup.getByLabel('Username').fill(usernameSecret);
    await popup.getByLabel('Password').fill(passwordSecret);

    const state = await dispatchLifecycleAndCapture(popup, scenario);
    expectClearedLifecycleState(state, [usernameSecret, passwordSecret]);

    const beforeCancellation = await fixtureSnapshot();
    expect(beforeCancellation.transactions).toContainEqual(expect.objectContaining({
      completed: false,
      transactionId: registrationBody.transactionId,
    }));
    expect(beforeCancellation.requests.filter(({ method, url }) => (
      method === 'POST' && url.endsWith(`/${registrationBody.transactionId}/result`)
    ))).toEqual([]);

    await destroyConsumerAndExpectCancellation(page, registrationBody);
  });
}

test('supports the complete login and confirmation keyboard path at 320 CSS pixels', async ({ browser }) => {
  test.setTimeout(60_000);
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    serviceWorkers: 'block',
    viewport: { height: 640, width: 320 },
  });
  const consumer = await context.newPage();
  const { popup, registrationBody } = await openPendingWallet(context, consumer);
  expect(popup.viewportSize()).toEqual({ height: 640, width: 320 });

  const username = popup.getByLabel('Username', { exact: true });
  const password = popup.getByLabel('Password', { exact: true });
  const remember = popup.getByLabel('Remember on this device', { exact: true });
  const login = popup.getByRole('button', { exact: true, name: 'Login' });
  const cancel = popup.getByRole('button', { exact: true, name: 'Cancel' });
  await expect(popup.getByRole('heading', { level: 1, name: 'Sign in to Space Data Network' }))
    .toBeVisible();
  await expect(username).toHaveAccessibleName('Username');
  await expect(password).toHaveAccessibleName('Password');
  await expect(remember).toHaveAccessibleName('Remember on this device');
  await expect(login).toHaveAccessibleName('Login');
  await expect(cancel).toHaveAccessibleName('Cancel');
  await expect(username).toBeFocused();

  const promptLayout = await popup.evaluate(() => {
    const root = document.querySelector('[data-wallet-origin-root]');
    const bounds = root?.getBoundingClientRect();
    return {
      innerWidth,
      rootLeft: bounds?.left,
      rootRight: bounds?.right,
      rootWidth: bounds?.width,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });
  expect(promptLayout).toEqual({
    innerWidth: 320,
    rootLeft: 0,
    rootRight: 320,
    rootWidth: 320,
    scrollWidth: 320,
  });

  await username.fill('  ALICE_01  ');
  await password.fill('Correct Horse Battery Staple!');
  await username.focus();
  await popup.keyboard.press('Tab');
  await expect(password).toBeFocused();
  await popup.keyboard.press('Tab');
  if (await remember.isEnabled()) {
    await expect(remember).toBeFocused();
    await popup.keyboard.press('Tab');
  }
  await expect(login).toBeFocused();
  await popup.keyboard.press('Enter');

  const confirmation = popup.getByRole('dialog', { name: 'Confirm wallet action' });
  await expect(confirmation).toBeVisible({ timeout: 20_000 });
  const confirm = confirmation.getByRole('button', { exact: true, name: 'Confirm' });
  const confirmationCancel = confirmation.getByRole('button', { exact: true, name: 'Cancel' });
  await expect(confirm).toBeFocused();
  await popup.keyboard.press('Tab');
  await expect(confirmationCancel).toBeFocused();
  await popup.keyboard.press('Tab');
  await expect(confirm).toBeFocused();
  await popup.keyboard.press('Shift+Tab');
  await expect(confirmationCancel).toBeFocused();

  const confirmationLayout = await popup.evaluate(() => ({
    innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(confirmationLayout).toEqual({ innerWidth: 320, scrollWidth: 320 });
  await popup.keyboard.press('Escape');
  await expect(popup.getByText('Cancelled. You may close this window.')).toBeVisible();
  await destroyConsumerAndExpectCancellation(consumer, registrationBody);
  await context.close();
});

test('has no service-worker registrations and rejects every non-fixture application request', async ({ context, page }) => {
  test.setTimeout(45_000);
  const pageRequests = [];
  context.on('request', (request) => pageRequests.push(request.url()));
  const { popup, registrationBody } = await openPendingWallet(context, page);
  expect(await serviceWorkerState(page)).toEqual({
    available: true,
    controlled: false,
    registrations: 0,
  });
  expect(await serviceWorkerState(popup)).toEqual({
    available: true,
    controlled: false,
    registrations: 0,
  });
  await destroyConsumerAndExpectCancellation(page, registrationBody);
  expect(pageRequests.every((url) => FROZEN_PAGE_ORIGINS.has(new URL(url).origin))).toBe(true);
  await assertNoUnexpectedApplicationRequests();
});
