import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const fixtureServer = fileURLToPath(new URL('./fixture-server.mjs', import.meta.url));

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  forbidOnly: true,
  outputDir: '/tmp/sdn-wallet-task11-playwright-results',
  reporter: [['line']],
  retries: 0,
  testDir: '.',
  testMatch: '*.spec.mjs',
  timeout: 30_000,
  use: {
    browserName: 'chromium',
    channel: 'chrome',
    headless: true,
    ignoreHTTPSErrors: true,
    proxy: { server: 'http://127.0.0.1:18776' },
    serviceWorkers: 'block',
    launchOptions: {
      args: [
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-default-apps',
        '--disable-domain-reliability',
        '--disable-features=AutofillServerCommunication,CaptivePortalDetection,OptimizationHints,MediaRouter',
        '--disable-sync',
        '--metrics-recording-only',
        '--no-first-run',
        '--safebrowsing-disable-auto-update',
      ],
    },
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `${JSON.stringify(process.execPath)} ${JSON.stringify(fixtureServer)}`,
    reuseExistingServer: false,
    timeout: 15_000,
    url: 'http://127.0.0.1:18776/healthz',
  },
  workers: 1,
});
