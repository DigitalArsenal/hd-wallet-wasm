/**
 * "Don't ask again for this site": a person's consent to open fields for one
 * site, remembered in the wallet origin's own storage for a short session.
 *
 * A grant names one client, origin, operation and account key, lasts at most
 * SESSION_MS and covers at most MAX_UNATTENDED openings (the rate limit on
 * openings nobody clicks for); after either, the wallet asks again. It holds
 * no key material. Logging out of the wallet forgets every grant.
 */

const STORAGE_KEY = 'sdn.wallet.consent.v1';
export const SESSION_MS = 15 * 60 * 1000;
export const MAX_UNATTENDED = 20;
const MAX_GRANTS = 16;

function readGrants(storage, now) {
  let grants = {};
  try {
    const parsed = JSON.parse(storage?.getItem?.(STORAGE_KEY) ?? '{}');
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) grants = parsed;
  } catch {
    grants = {};
  }
  const live = {};
  for (const [scope, grant] of Object.entries(grants)) {
    if (Number.isSafeInteger(grant?.expiresAt) && grant.expiresAt > now && grant.expiresAt - now <= SESSION_MS
        && Number.isSafeInteger(grant?.remaining) && grant.remaining > 0 && grant.remaining <= MAX_UNATTENDED) {
      live[scope] = { expiresAt: grant.expiresAt, remaining: grant.remaining };
    }
  }
  return live;
}

function writeGrants(storage, grants) {
  try {
    if (Object.keys(grants).length === 0) storage?.removeItem?.(STORAGE_KEY);
    else storage?.setItem?.(STORAGE_KEY, JSON.stringify(grants));
    return true;
  } catch {
    return false;
  }
}

/** The scope one grant covers, or null when the operation is never remembered. */
export function consentScope(binding, identity) {
  if (binding?.operation !== 'sdn.wallet.field-open.v1' && binding?.operation !== 'sdn.wallet.key-unwrap.v1') {
    return null;
  }
  const key = identity?.keys?.find?.((candidate) => candidate?.purpose === 'contact-encryption');
  if (typeof key?.keyId !== 'string') return null;
  return [binding.clientId, binding.requestOrigin, binding.operation, key.keyId].join('|');
}

export function createConsentMemory({ storage, now = () => Date.now() }) {
  return Object.freeze({
    /** Uses one unattended opening of a live grant; false means ask. */
    take(scope) {
      if (!scope) return false;
      const grants = readGrants(storage, now());
      const grant = grants[scope];
      if (!grant) return false;
      grant.remaining -= 1;
      if (grant.remaining === 0) delete grants[scope];
      return writeGrants(storage, grants);
    },
    grant(scope) {
      if (!scope) return;
      const time = now();
      const grants = readGrants(storage, time);
      grants[scope] = { expiresAt: time + SESSION_MS, remaining: MAX_UNATTENDED };
      const scopes = Object.keys(grants);
      if (scopes.length > MAX_GRANTS) {
        scopes.sort((left, right) => grants[left].expiresAt - grants[right].expiresAt);
        for (const old of scopes.slice(0, scopes.length - MAX_GRANTS)) delete grants[old];
      }
      writeGrants(storage, grants);
    },
    clear() {
      writeGrants(storage, {});
    },
  });
}
