export function normalizeTabHash(rawHash) {
  return String(rawHash || '')
    .replace(/^#+/g, '')
    .replace(/^\/+/g, '')
    .split(/[/?#]/)[0]
    .replace(/[^a-z0-9_-]/gi, '')
    .replace(/-tab$/i, '')
    .toLowerCase();
}
