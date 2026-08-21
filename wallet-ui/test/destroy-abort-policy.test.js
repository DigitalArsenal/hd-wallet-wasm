import { describe, expect, it } from 'vitest';

import { assertIntentionalDestroyAbortFailures } from './browser/destroy-abort-policy.mjs';

const pollUrl = `https://wallet.spacedatanetwork.org/relay/v1/transactions/${'a'.repeat(64)}`;
const cancelUrl = `${pollUrl}/cancel`;
const aborted = (url) => ({ error: 'net::ERR_ABORTED', url });

describe('destroy request-failure policy', () => {
  it('accepts the platform variants after the exact cancellation reaches the fixture', () => {
    expect(() => assertIntentionalDestroyAbortFailures(
      [aborted(cancelUrl)],
      { cancelUrl, pollUrl },
    )).not.toThrow();
    expect(() => assertIntentionalDestroyAbortFailures(
      [aborted(pollUrl), aborted(cancelUrl)],
      { cancelUrl, pollUrl },
    )).not.toThrow();
  });

  it.each([
    [],
    [aborted(pollUrl)],
    [aborted(cancelUrl), aborted(cancelUrl)],
    [aborted(pollUrl), aborted(cancelUrl), aborted(pollUrl)],
    [{ error: 'net::ERR_FAILED', url: cancelUrl }],
    [aborted('https://example.invalid/elsewhere')],
  ])('rejects missing, duplicate, excessive, differently failed, or foreign requests: %j', (failures) => {
    expect(() => assertIntentionalDestroyAbortFailures(
      failures,
      { cancelUrl, pollUrl },
    )).toThrow();
  });
});
