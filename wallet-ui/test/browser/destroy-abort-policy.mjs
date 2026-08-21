export function assertIntentionalDestroyAbortFailures(failures, { cancelUrl, pollUrl }) {
  if (!Array.isArray(failures) || failures.length < 1 || failures.length > 2) {
    throw new Error('destroy must abort exactly the cancellation and, at most, its in-flight poll');
  }
  const allowedUrls = new Set([cancelUrl, pollUrl]);
  const observedUrls = new Set();
  for (const failure of failures) {
    if (
      failure === null ||
      typeof failure !== 'object' ||
      Array.isArray(failure) ||
      Object.keys(failure).sort().join(',') !== 'error,url' ||
      failure.error !== 'net::ERR_ABORTED' ||
      !allowedUrls.has(failure.url) ||
      observedUrls.has(failure.url)
    ) {
      throw new Error('destroy observed an unexpected, duplicate, or non-abort request failure');
    }
    observedUrls.add(failure.url);
  }
  if (!observedUrls.has(cancelUrl)) {
    throw new Error('destroy did not observe the exact cancellation abort');
  }
}
