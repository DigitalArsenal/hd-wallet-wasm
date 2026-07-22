import { expect, test } from '@playwright/test';

import { assertIntentionalDestroyAbortFailures } from './destroy-abort-policy.mjs';

const FIXTURE_CONTROL_ORIGIN = 'http://127.0.0.1:18776';
const CONSUMER_ORIGIN = 'https://spacedatanetwork.org';
const WALLET_ORIGIN = 'https://wallet.spacedatanetwork.org';
const HOSTILE_COLOR = 'rgb(255, 0, 255)';
const USERNAME = 'HOSTILE_OBSERVER_91';
const PASSWORD = 'Consumer-Cannot-Read#2026!';

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

function observePage(page, diagnostics) {
  page.on('console', (message) => diagnostics.console.push({
    location: message.location(),
    text: message.text(),
    type: message.type(),
    url: page.url(),
  }));
  page.on('pageerror', (error) => diagnostics.pageErrors.push({
    message: error.message,
    url: page.url(),
  }));
}

function normalizedRequests(snapshot, transactionId) {
  return snapshot.requests
    .filter(({ url }) => url !== '/favicon.ico')
    .map(({ host, method, scope, url }) => {
      if (/^\/assets\/hd-wallet-ui\/[0-9]+\.[0-9]+\.[0-9]+\/(?:consumer-instrumentation|consumer-presenter)\.[0-9a-f]{64}\.js$/u.test(url)) {
        return `${scope}|${host}|${method}|${url.replace(/\.[0-9a-f]{64}\.js$/u, '.<sha256>.js')}`;
      }
      if (/^\/assets\/hd-wallet-ui\/[0-9]+\.[0-9]+\.[0-9]+\/sdn-wallet-public-client\.[0-9a-f]{64}\.(?:css|js)$/u.test(url)) {
        return `${scope}|${host}|${method}|${url.replace(/\.[0-9a-f]{64}\.(css|js)$/u, '.<sha256>.$1')}`;
      }
      if (/^\/assets\/wallet-origin\.[0-9a-f]{64}\.(?:css|js|wasm)$/u.test(url)) {
        return `${scope}|${host}|${method}|${url.replace(/\.[0-9a-f]{64}\.(css|js|wasm)$/u, '.<sha256>.$1')}`;
      }
      return `${scope}|${host}|${method}|${url.replace(transactionId, '<transaction>')}`;
    })
    .sort();
}

test.beforeEach(async () => {
  await resetFixture();
});

test.afterEach(async () => {
  const snapshot = await fixtureSnapshot();
  expect(snapshot.unexpected).toEqual([]);
  const exactBrowserProbes = new Set([
    'consumer|spacedatanetwork.org|GET|/favicon.ico',
    'consumer|static.spacedatanetwork.org|GET|/favicon.ico',
    'proxy|content-autofill.googleapis.com:443|CONNECT|content-autofill.googleapis.com:443',
    'proxy|www.google.com:443|CONNECT|www.google.com:443',
    'wallet|wallet.spacedatanetwork.org|GET|/favicon.ico',
  ]);
  expect(snapshot.browserProbes.every(({ host, method, scope, url }) => (
    exactBrowserProbes.has([scope, host, method, url].join('|'))
  ))).toBe(true);
});

test('keeps wallet credential controls outside a hostile consumer page', async ({ browser }) => {
  test.setTimeout(45_000);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const diagnostics = {
    console: [],
    failedResponses: [],
    pageErrors: [],
    requestBodies: [],
    requestFailures: [],
  };
  const page = await context.newPage();
  observePage(page, diagnostics);
  context.on('page', (openedPage) => observePage(openedPage, diagnostics));
  context.on('request', (request) => {
    if (request.postData() !== null) diagnostics.requestBodies.push(request.postData());
  });
  context.on('requestfailed', (request) => diagnostics.requestFailures.push({
    error: request.failure()?.errorText ?? '',
    url: request.url(),
  }));
  context.on('response', (response) => {
    if (response.status() >= 400) diagnostics.failedResponses.push({
      status: response.status(),
      url: response.url(),
    });
  });

  await page.goto(`${CONSUMER_ORIGIN}/harness`);
  await page.evaluate(() => {
    const observations = {
      controlsCreated: [],
      events: [],
      inputValues: [],
      logs: [],
      mutations: [],
      openCalls: [],
      storage: [],
      windowListeners: [],
    };
    const appendBounded = (target, value) => {
      if (target.length < 256) target.push(value);
    };
    const safeText = (value, maximum = 1_024) => String(value ?? '').slice(0, maximum);
    const describeNode = (node) => {
      if (node?.nodeType === Node.ELEMENT_NODE) return safeText(node.outerHTML);
      return safeText(node?.textContent);
    };
    const describeEvent = (event) => {
      const target = event.target;
      let value = null;
      try {
        if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
          value = target.value;
        }
      } catch {
        value = '<unavailable>';
      }
      return {
        target: describeNode(target),
        trusted: event.isTrusted,
        type: event.type,
        value,
      };
    };

    const mutationObserver = new MutationObserver((records) => {
      for (const record of records) {
        appendBounded(observations.mutations, {
          added: [...record.addedNodes].map(describeNode),
          attributeName: record.attributeName,
          oldValue: safeText(record.oldValue),
          target: describeNode(record.target),
          type: record.type,
        });
      }
    });
    mutationObserver.observe(document.documentElement, {
      attributeOldValue: true,
      attributes: true,
      characterData: true,
      childList: true,
      subtree: true,
    });

    for (const type of ['beforeinput', 'change', 'click', 'input', 'keydown', 'submit']) {
      document.addEventListener(type, (event) => {
        appendBounded(observations.events, describeEvent(event));
      }, true);
    }

    const nativeCreateElement = document.createElement;
    document.createElement = function (localName, options) {
      const element = Reflect.apply(nativeCreateElement, this, [localName, options]);
      if (['button', 'form', 'input', 'label', 'textarea'].includes(String(localName).toLowerCase())) {
        appendBounded(observations.controlsCreated, String(localName).toLowerCase());
      }
      return element;
    };

    const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    Object.defineProperty(HTMLInputElement.prototype, 'value', {
      configurable: valueDescriptor.configurable,
      enumerable: valueDescriptor.enumerable,
      get() {
        const value = Reflect.apply(valueDescriptor.get, this, []);
        appendBounded(observations.inputValues, { kind: 'get', value: safeText(value) });
        return value;
      },
      set(value) {
        appendBounded(observations.inputValues, { kind: 'set', value: safeText(value) });
        return Reflect.apply(valueDescriptor.set, this, [value]);
      },
    });

    for (const name of ['debug', 'error', 'info', 'log', 'warn']) {
      const nativeMethod = console[name];
      console[name] = function (...values) {
        appendBounded(observations.logs, {
          name,
          values: values.map((value) => safeText(value)),
        });
        return Reflect.apply(nativeMethod, this, values);
      };
    }

    for (const name of ['clear', 'getItem', 'key', 'removeItem', 'setItem']) {
      const nativeMethod = Storage.prototype[name];
      Storage.prototype[name] = function (...values) {
        appendBounded(observations.storage, {
          name,
          values: values.map((value) => safeText(value)),
        });
        return Reflect.apply(nativeMethod, this, values);
      };
    }

    for (const name of ['addEventListener', 'removeEventListener']) {
      const nativeMethod = window[name];
      window[name] = function (type, ...values) {
        appendBounded(observations.windowListeners, { name, type: safeText(type) });
        return Reflect.apply(nativeMethod, this, [type, ...values]);
      };
    }

    const instrumentedOpen = window.open;
    let popupHandle = undefined;
    window.open = function (...values) {
      const call = {
        args: values.map((value) => safeText(value)),
        sync: globalThis.__walletTest?.inTrustedHandler === true,
      };
      appendBounded(observations.openCalls, call);
      popupHandle = Reflect.apply(instrumentedOpen, this, values);
      call.returnedNull = popupHandle === null;
      return popupHandle;
    };

    const hostileSheet = new CSSStyleSheet();
    hostileSheet.replaceSync(`
      * { color: rgb(255, 0, 255) !important; cursor: crosshair !important; }
      input, textarea, form, label, [autocomplete] {
        all: unset !important;
        display: none !important;
        inset: 0 !important;
        opacity: .01 !important;
        pointer-events: none !important;
        position: fixed !important;
      }
      [data-hostile-overlay] {
        background: rgba(255, 0, 255, .25) !important;
        inset: 0 !important;
        pointer-events: none !important;
        position: fixed !important;
        z-index: 2147483647 !important;
      }
    `);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, hostileSheet];

    const decoy = document.createElement('input');
    decoy.dataset.hostileDecoy = 'true';
    decoy.name = 'consumer-decoy';
    decoy.type = 'text';
    decoy.value = 'consumer-observer-probe';
    const overlay = document.createElement('div');
    overlay.dataset.hostileOverlay = 'true';
    overlay.setAttribute('aria-hidden', 'true');
    overlay.textContent = 'Hostile consumer overlay';
    document.body.append(decoy, overlay);
    localStorage.setItem('hostile-observer-probe', 'armed');
    localStorage.removeItem('hostile-observer-probe');

    Object.defineProperty(globalThis, '__hostileConsumer', {
      configurable: false,
      enumerable: false,
      value: {
        decoy,
        mutationObserver,
        observations,
        overlay,
        popupHandle: () => popupHandle,
      },
      writable: false,
    });
  });

  const poisonEvidence = await page.evaluate(() => {
    const hostile = globalThis.__hostileConsumer;
    const decoy = getComputedStyle(hostile.decoy);
    const overlay = getComputedStyle(hostile.overlay);
    const presenter = getComputedStyle(document.querySelector('[data-wallet-presenter] button'));
    return {
      decoy: {
        color: decoy.color,
        display: decoy.display,
        opacity: decoy.opacity,
        pointerEvents: decoy.pointerEvents,
        position: decoy.position,
      },
      overlay: {
        bottom: overlay.bottom,
        left: overlay.left,
        pointerEvents: overlay.pointerEvents,
        position: overlay.position,
        right: overlay.right,
        top: overlay.top,
        zIndex: overlay.zIndex,
      },
      presenterColor: presenter.color,
    };
  });
  expect(poisonEvidence).toEqual({
    decoy: {
      color: HOSTILE_COLOR,
      display: 'none',
      opacity: '0.01',
      pointerEvents: 'none',
      position: 'fixed',
    },
    overlay: {
      bottom: '0px',
      left: '0px',
      pointerEvents: 'none',
      position: 'fixed',
      right: '0px',
      top: '0px',
      zIndex: '2147483647',
    },
    presenterColor: HOSTILE_COLOR,
  });

  const registrationPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions`);
  const popupPromise = context.waitForEvent('page');
  await page.locator('[data-wallet-presenter] button').first().click();
  const [registration, popup] = await Promise.all([registrationPromise, popupPromise]);
  const registrationBody = registration.postDataJSON();
  expect(registrationBody).toMatchObject({
    clientId: 'sdn-landing-web-v1',
    operation: 'sdn.wallet.connect.v1',
    request: {},
    schemaVersion: 1,
  });
  expect(registrationBody.transactionId).toMatch(/^[0-9a-f]{64}$/u);
  await expect.poll(() => popup.url()).toBe(
    `${WALLET_ORIGIN}/transaction/${registrationBody.transactionId}`,
  );
  expect(await popup.evaluate(() => window.opener === null)).toBe(true);

  const openingEvidence = await page.evaluate(() => ({
    hostileOpen: globalThis.__hostileConsumer.observations.openCalls,
    popupHandleNull: globalThis.__hostileConsumer.popupHandle() === null,
    publicEvents: globalThis.__walletTest.events,
    windowFrames: window.frames.length,
  }));
  expect(openingEvidence.publicEvents.map(({ kind }) => kind)).toEqual([
    'trusted-click',
    'connect-enter',
    'popup-open',
    'popup-return',
    'connect-return',
    'handler-return',
  ]);
  expect(openingEvidence.publicEvents[2]).toMatchObject({
    args: [
      `${WALLET_ORIGIN}/transaction/${registrationBody.transactionId}`,
      '_blank',
      'noopener',
    ],
    sync: true,
  });
  expect(openingEvidence.hostileOpen).toEqual([{
    args: [
      `${WALLET_ORIGIN}/transaction/${registrationBody.transactionId}`,
      '_blank',
      'noopener',
    ],
    returnedNull: true,
    sync: true,
  }]);
  expect(openingEvidence).toMatchObject({ popupHandleNull: true, windowFrames: 0 });

  const username = popup.getByLabel('Username');
  const password = popup.getByLabel('Password');
  await expect(username).toBeVisible({ timeout: 20_000 });
  await expect(password).toBeVisible();
  await username.fill(USERNAME);
  await password.fill(PASSWORD);
  await expect(username).toHaveValue(USERNAME);
  await expect(password).toHaveValue(PASSWORD);

  const walletOwnership = await popup.evaluate(() => {
    const usernameControl = document.querySelector('input[name="username"]');
    const passwordControl = document.querySelector('input[name="password"]');
    const describe = (control) => {
      const style = getComputedStyle(control);
      const bounds = control.getBoundingClientRect();
      return {
        backgroundColor: style.backgroundColor,
        color: style.color,
        display: style.display,
        height: bounds.height,
        opacity: style.opacity,
        ownerOrigin: control.ownerDocument.location.origin,
        pointerEvents: style.pointerEvents,
        position: style.position,
        visibility: style.visibility,
        width: bounds.width,
      };
    };
    return {
      controls: [describe(usernameControl), describe(passwordControl)],
      hostileOverlayPresent: document.querySelector('[data-hostile-overlay]') !== null,
      origin: location.origin,
      scripts: [...document.scripts].map(({ src }) => src),
      sentinel: getComputedStyle(document.documentElement)
        .getPropertyValue('--sdn-wallet-origin-style-ready').trim(),
      stylesheets: [...document.styleSheets].map(({ href }) => href),
    };
  });
  expect(walletOwnership.origin).toBe(WALLET_ORIGIN);
  expect(walletOwnership.hostileOverlayPresent).toBe(false);
  expect(walletOwnership.sentinel).toBe('"2.0.28"');
  expect(walletOwnership.stylesheets).toHaveLength(1);
  expect(walletOwnership.stylesheets[0]).toMatch(
    /^https:\/\/wallet\.spacedatanetwork\.org\/assets\/wallet-origin\.[0-9a-f]{64}\.css$/u,
  );
  expect(walletOwnership.scripts).toHaveLength(1);
  expect(walletOwnership.scripts[0]).toMatch(
    /^https:\/\/wallet\.spacedatanetwork\.org\/assets\/wallet-origin\.[0-9a-f]{64}\.js$/u,
  );
  for (const control of walletOwnership.controls) {
    expect(control).toMatchObject({
      backgroundColor: 'rgb(8, 20, 38)',
      color: 'rgb(245, 247, 255)',
      opacity: '1',
      ownerOrigin: WALLET_ORIGIN,
      pointerEvents: 'auto',
      position: 'static',
      visibility: 'visible',
    });
    expect(control.display).not.toBe('none');
    expect(control.color).not.toBe(HOSTILE_COLOR);
    expect(control.height).toBeGreaterThan(0);
    expect(control.width).toBeGreaterThan(0);
  }

  const cancelPromise = page.waitForRequest((request) => request.method() === 'POST'
    && request.url() === `${WALLET_ORIGIN}/relay/v1/transactions/${registrationBody.transactionId}/cancel`);
  await popup.close();
  expect(popup.isClosed()).toBe(true);
  const destroyedSnapshot = await page.evaluate(async () => {
    await globalThis.__walletTest.client.destroy();
    const snapshot = globalThis.__walletTest.client.getSnapshot();
    globalThis.__walletTest.unsubscribe();
    globalThis.__hostileConsumer.mutationObserver.disconnect();
    return snapshot;
  });
  const cancel = await cancelPromise;
  expect(cancel.postDataJSON()).toMatchObject({
    schemaVersion: 1,
    state: registrationBody.state,
    transactionId: registrationBody.transactionId,
  });
  expect(destroyedSnapshot).toEqual({
    error: {
      code: 'DESTROYED',
      message: 'This wallet client has been destroyed.',
    },
    identity: null,
    status: 'error',
  });

  const consumerEvidence = await page.evaluate(() => {
    const hostile = globalThis.__hostileConsumer;
    return {
      controls: [...document.querySelectorAll('input, textarea')].map((control) => ({
        attributes: [...control.attributes].map(({ name, value }) => [name, value]),
        defaultValue: control.defaultValue,
        value: control.value,
      })),
      dom: document.documentElement.outerHTML,
      hostile: {
        controlsCreated: hostile.observations.controlsCreated,
        events: hostile.observations.events,
        inputValues: hostile.observations.inputValues,
        logs: hostile.observations.logs,
        mutations: hostile.observations.mutations,
        openCalls: hostile.observations.openCalls,
        popupHandleNull: hostile.popupHandle() === null,
        storage: hostile.observations.storage,
        windowListeners: hostile.observations.windowListeners,
      },
      publicEvents: globalThis.__walletTest.events,
      storage: Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]),
    };
  });
  expect(consumerEvidence.controls).toEqual([{
    attributes: [
      ['data-hostile-decoy', 'true'],
      ['name', 'consumer-decoy'],
      ['type', 'text'],
    ],
    defaultValue: '',
    value: 'consumer-observer-probe',
  }]);
  expect(consumerEvidence.hostile.controlsCreated).toContain('input');
  expect(consumerEvidence.hostile.events.some(({ trusted, type }) => (
    trusted === true && type === 'click'
  ))).toBe(true);
  expect(consumerEvidence.hostile.inputValues).toContainEqual({
    kind: 'set',
    value: 'consumer-observer-probe',
  });
  expect(consumerEvidence.hostile.mutations.length).toBeGreaterThan(0);
  expect(consumerEvidence.hostile.storage).toEqual(expect.arrayContaining([
    { name: 'setItem', values: ['hostile-observer-probe', 'armed'] },
    { name: 'removeItem', values: ['hostile-observer-probe'] },
  ]));
  expect(consumerEvidence.hostile.windowListeners).toEqual(expect.arrayContaining([
    { name: 'addEventListener', type: 'storage' },
    { name: 'removeEventListener', type: 'storage' },
  ]));
  expect(consumerEvidence.hostile.popupHandleNull).toBe(true);
  expect(consumerEvidence.storage).toEqual([]);

  const fixture = await fixtureSnapshot();
  const allConsumerObservable = JSON.stringify({
    consumerEvidence,
    console: diagnostics.console.filter(({ url }) => url.startsWith(CONSUMER_ORIGIN)),
    fixture,
    requestBodies: diagnostics.requestBodies,
  });
  for (const secret of [
    USERNAME,
    USERNAME.toLowerCase(),
    PASSWORD,
    Buffer.from(USERNAME).toString('base64'),
    Buffer.from(USERNAME).toString('hex'),
    Buffer.from(PASSWORD).toString('base64'),
    Buffer.from(PASSWORD).toString('hex'),
  ]) {
    expect(allConsumerObservable).not.toContain(secret);
  }

  expect(normalizedRequests(fixture, registrationBody.transactionId)).toEqual([
    'consumer|spacedatanetwork.org|GET|/assets/hd-wallet-ui/2.0.28/consumer-instrumentation.<sha256>.js',
    'consumer|spacedatanetwork.org|GET|/assets/hd-wallet-ui/2.0.28/consumer-presenter.<sha256>.js',
    'consumer|spacedatanetwork.org|GET|/harness',
    'consumer|static.spacedatanetwork.org|GET|/assets/hd-wallet-ui/2.0.28/sdn-wallet-public-client.<sha256>.css',
    'consumer|static.spacedatanetwork.org|GET|/assets/hd-wallet-ui/2.0.28/sdn-wallet-public-client.<sha256>.js',
    'wallet|wallet.spacedatanetwork.org|GET|/assets/wallet-origin.<sha256>.css',
    'wallet|wallet.spacedatanetwork.org|GET|/assets/wallet-origin.<sha256>.js',
    'wallet|wallet.spacedatanetwork.org|GET|/assets/wallet-origin.<sha256>.wasm',
    'wallet|wallet.spacedatanetwork.org|GET|/relay/v1/transactions/<transaction>',
    'wallet|wallet.spacedatanetwork.org|GET|/transaction/<transaction>',
    'wallet|wallet.spacedatanetwork.org|OPTIONS|/relay/v1/transactions',
    'wallet|wallet.spacedatanetwork.org|OPTIONS|/relay/v1/transactions/<transaction>/cancel',
    'wallet|wallet.spacedatanetwork.org|POST|/relay/v1/transactions',
    'wallet|wallet.spacedatanetwork.org|POST|/relay/v1/transactions/<transaction>/cancel',
  ]);
  expect(fixture.transactions).toEqual([]);
  expect(diagnostics.pageErrors).toEqual([]);
  // Chromium reports the deliberately aborted empty cancellation body on every
  // platform and, on Linux, also reports the in-flight poll aborted by destroy().
  // The exact fixture ledger above proves both requests stayed on their frozen
  // routes and that cancellation removed the transaction.
  assertIntentionalDestroyAbortFailures(diagnostics.requestFailures, {
    cancelUrl: `${WALLET_ORIGIN}/relay/v1/transactions/${registrationBody.transactionId}/cancel`,
    pollUrl: `${WALLET_ORIGIN}/relay/v1/transactions/${registrationBody.transactionId}`,
  });
  expect(diagnostics.failedResponses.every(({ status, url }) => (
    status === 404 && url === `${WALLET_ORIGIN}/favicon.ico`
  ))).toBe(true);
  const unexpectedConsole = diagnostics.console.filter(({ location, text, type }) => {
    const ignoredMetaFrameAncestors = type === 'error'
      && text === "The Content Security Policy directive 'frame-ancestors' is ignored when delivered via a <meta> element.";
    const expectedFaviconProbe = type === 'error'
      && text === 'Failed to load resource: the server responded with a status of 404 (Not Found)'
      && location.url === `${WALLET_ORIGIN}/favicon.ico`;
    return !ignoredMetaFrameAncestors && !expectedFaviconProbe;
  });
  expect(unexpectedConsole).toEqual([]);
  await context.close();
});
