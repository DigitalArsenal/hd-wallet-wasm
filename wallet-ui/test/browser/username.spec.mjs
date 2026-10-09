import { expect, test } from '@playwright/test';

// A username and password derive one deterministic wallet. Any username of
// 3-64 UTF-8 bytes (after trimming spaces) without control characters signs in.
const FIXTURE_CONTROL_ORIGIN = 'http://127.0.0.1:18776';
const WALLET_ORIGIN = 'https://wallet.spacedatanetwork.org';
const PASSWORD = 'Correct Horse Battery Staple!';

// sdn-authentication public keys for PASSWORD. alpha.ops is the value the
// published hd-wallet-wasm 2.0.32 derives; the others were first accepted in 2.0.33.
const AUTHENTICATION_KEYS = Object.freeze({
  'alpha.ops': '4b152b715550b8a67909a5ceb739e0e2f7d60a974743023bec24bd163f59825f',
  'mission control': '37569a1737099a7450a18ea82725a48d6ffdfe94760b9fda12a51179083bb81b',
  'ops@example.org': '69a4a17bfb31f928765de4eb1917131828bc6ceadff8d49557f1fadb5b0eb03f',
  'Ωmega-7': '6eb4f2f4ae960a8f8e812830136f773d0b826ee37903f081b15379882f929a36',
});

test.use({
  browserName: 'chromium',
  channel: 'chrome',
  headless: true,
  ignoreHTTPSErrors: true,
  proxy: { server: FIXTURE_CONTROL_ORIGIN },
  serviceWorkers: 'block',
});

function fixtureControl(path, init) {
  return fetch(new URL(path, FIXTURE_CONTROL_ORIGIN).href, init);
}

test.beforeEach(async () => {
  expect((await fixtureControl('/__fixture/reset', { method: 'POST' })).status).toBe(204);
});

test.afterEach(async () => {
  const snapshot = await (await fixtureControl('/__fixture/snapshot')).json();
  expect(snapshot.unexpected).toEqual([]);
});

async function signIn(browser, username, run) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block' });
  try {
    const consumer = await context.newPage();
    await consumer.goto('https://spacedatanetwork.org/harness');
    const registrationPromise = consumer.waitForRequest((request) => request.method() === 'POST'
      && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions`);
    const popupPromise = context.waitForEvent('page');
    await consumer.locator('[data-wallet-presenter] button').first().click();
    const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
    const { transactionId } = registration.postDataJSON();
    await expect(popup.getByLabel('Username', { exact: true })).toBeVisible({ timeout: 20_000 });
    await popup.getByLabel('Username', { exact: true }).fill(username);
    await popup.getByLabel('Password', { exact: true }).fill(PASSWORD);
    await popup.getByRole('button', { exact: true, name: 'Login' }).click();
    return await run({ popup, transactionId });
  } finally {
    await context.close();
  }
}

async function connectedAuthenticationKey(browser, username) {
  return signIn(browser, username, async ({ popup, transactionId }) => {
    const publication = popup.waitForRequest((request) => request.method() === 'POST'
      && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions/${transactionId}/result`);
    await popup.getByRole('button', { exact: true, name: 'Connect' }).click({ timeout: 20_000 });
    const { result } = (await publication).postDataJSON();
    expect(result.event).toBe('connected');
    return result.identity.keys.find(({ purpose }) => purpose === 'sdn-authentication').publicKeyHex;
  });
}

async function expectRefused(browser, username) {
  await signIn(browser, username, async ({ popup, transactionId }) => {
    await expect(popup.locator('.wallet-terminal-error')).toHaveCount(1, { timeout: 20_000 });
    await expect(popup.getByLabel('Password', { exact: true })).toHaveCount(0);
    const snapshot = await (await fixtureControl('/__fixture/snapshot')).json();
    expect(snapshot.requests.filter(({ method, url }) => (
      method === 'POST' && url === `/relay/v1/transactions/${transactionId}/result`
    ))).toEqual([]);
  });
}

for (const username of ['ops@example.org', 'mission control', 'Ωmega-7']) {
  test(`${username} derives the same wallet on every sign-in`, async ({ browser }) => {
    test.setTimeout(90_000);
    expect(await connectedAuthenticationKey(browser, username)).toBe(AUTHENTICATION_KEYS[username]);
    expect(await connectedAuthenticationKey(browser, username)).toBe(AUTHENTICATION_KEYS[username]);
  });
}

test('alpha.ops derives exactly the 2.0.32 wallet', async ({ browser }) => {
  test.setTimeout(60_000);
  expect(await connectedAuthenticationKey(browser, 'alpha.ops')).toBe(AUTHENTICATION_KEYS['alpha.ops']);
});

for (const [title, username] of [
  ['a 2-byte username', 'ab'],
  ['a 65-byte username', 'a'.repeat(65)],
  ['a username with a control character', 'ops\u0001team'],
]) {
  test(`${title} does not sign in`, async ({ browser }) => {
    test.setTimeout(60_000);
    await expectRefused(browser, username);
  });
}
