/**
 * Balance scanning for the current account's addresses (Assets).
 *
 * One scan covers exactly the addresses it is given — the three of account N,
 * or the connected address of an external session — one request each, with
 * the wallet's existing behaviour kept: a 2-minute cache, a 30-minute stale
 * fallback, a pause between requests, retries with back-off and a per-chain
 * cool-down after a rate limit. The cache lives wherever the caller keeps it
 * (hdw:<fp>:a<N>:scan-cache for a seed session).
 */

export const BALANCE_CACHE_TTL_MS = 2 * 60 * 1000;
export const BALANCE_CACHE_STALE_MS = 30 * 60 * 1000;

export function isNumericBalance(balance) {
  const n = Number.parseFloat(balance);
  return Number.isFinite(n) && n >= 0;
}

export function isRateLimitError(message) {
  const text = String(message || '').toLowerCase();
  return text.includes('429')
    || text.includes('rate')
    || text.includes('limit')
    || text.includes('too many')
    || text.includes('throttl')
    || text.includes('quota');
}

const CANCELLED = Object.freeze({
  balance: '--',
  cancelled: true,
  error: 'Wallet session ended',
  ok: false,
  source: 'none',
  stale: false,
});

/**
 * @param {object} options
 * @param {Record<string, (address: string) => Promise<{balance?: string, error?: string}>>} options.fetchers
 * @param {() => object} options.readCache
 * @param {(cache: object) => void} options.writeCache
 * @param {() => number} [options.now]
 * @param {(ms: number) => Promise<void>} [options.sleep]
 */
export function createBalanceScanner({
  fetchers,
  readCache,
  writeCache,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  requestDelayMs = 700,
  retryBaseMs = 1200,
  maxRetries = 2,
  ttlMs = BALANCE_CACHE_TTL_MS,
  staleMs = BALANCE_CACHE_STALE_MS,
  cooldownMs = 2 * 60 * 1000,
}) {
  let lastRequestAt = 0;
  let rateLimitUntil = {};

  function cached(chain, address, { allowStale = false } = {}) {
    const entry = readCache()?.[`${chain}:${address}`];
    if (!entry || typeof entry.balance !== 'string' || typeof entry.ts !== 'number') return null;
    const age = now() - entry.ts;
    if (age <= ttlMs) return { ...entry, stale: false };
    if (allowStale && age <= staleMs) return { ...entry, stale: true };
    return null;
  }

  function remember(chain, address, balance) {
    if (!isNumericBalance(balance)) return;
    const cache = { ...(readCache() ?? {}) };
    cache[`${chain}:${address}`] = { balance: String(balance), ts: now() };
    const time = now();
    for (const [key, entry] of Object.entries(cache)) {
      if (!entry || typeof entry.ts !== 'number' || time - entry.ts > staleMs) delete cache[key];
    }
    writeCache(cache);
  }

  async function throttle(isCurrent) {
    const elapsed = now() - lastRequestAt;
    if (elapsed < requestDelayMs) await sleep(requestDelayMs - elapsed);
    if (!isCurrent()) return false;
    lastRequestAt = now();
    return true;
  }

  /** The balance of one address: cache first, then the network with retries. */
  async function fetchBalance({ chain, address }, isCurrent, { force = false } = {}) {
    if (!isCurrent()) return CANCELLED;
    if (now() < (rateLimitUntil[chain] || 0)) {
      const stale = cached(chain, address, { allowStale: true });
      if (stale) return { ok: true, balance: stale.balance, source: 'cache', stale: true, error: 'Rate-limited; using cached balance' };
      return { ok: false, balance: '--', source: 'none', stale: false, error: 'Rate-limited; retrying later' };
    }
    const fresh = force ? null : cached(chain, address);
    if (fresh) return { ok: true, balance: fresh.balance, source: 'cache', stale: false };

    const fetcher = fetchers[chain];
    let lastError = fetcher ? '' : `No balance source for ${chain}`;
    for (let attempt = 0; fetcher && attempt <= maxRetries; attempt += 1) {
      if (!await throttle(isCurrent)) return CANCELLED;
      try {
        const result = await fetcher(address);
        if (!isCurrent()) return CANCELLED;
        if (!result?.error && isNumericBalance(result?.balance)) {
          rateLimitUntil[chain] = 0;
          remember(chain, address, result.balance);
          return { ok: true, balance: String(result.balance), source: 'network', stale: false };
        }
        lastError = result?.error || 'Unknown balance fetch error';
      } catch (error) {
        if (!isCurrent()) return CANCELLED;
        lastError = error?.message || 'Unknown balance fetch exception';
      }
      if (isRateLimitError(lastError)) rateLimitUntil[chain] = now() + cooldownMs;
      if (attempt < maxRetries) {
        await sleep(retryBaseMs * (attempt + 1));
        if (!isCurrent()) return CANCELLED;
      }
    }

    if (!isCurrent()) return CANCELLED;
    const stale = cached(chain, address, { allowStale: true });
    if (stale) return { ok: true, balance: stale.balance, source: 'cache', stale: true, error: lastError };
    return { ok: false, balance: '--', source: 'none', stale: false, error: lastError || 'Balance unavailable' };
  }

  /**
   * Scan every target once. Resolves to `{ balances, failures, cancelled }`.
   */
  async function scan(targets, isCurrent, { force = false } = {}) {
    const balances = {};
    let failures = 0;
    for (const target of targets) {
      const result = await fetchBalance(target, isCurrent, { force });
      if (result.cancelled) return { balances, failures, cancelled: true };
      if (result.ok) balances[target.chain] = result.balance;
      else failures += 1;
    }
    return { balances, failures, cancelled: false };
  }

  return Object.freeze({
    fetchBalance,
    scan,
    cached,
    reset() {
      lastRequestAt = 0;
      rateLimitUntil = {};
    },
  });
}
