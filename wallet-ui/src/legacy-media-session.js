const intrinsicFill = Uint8Array.prototype.fill;
const MAX_PHOTO_FILE_BYTES = 2 * 1024 * 1024;

function exactBoundedFileSize(file, maximumBytes) {
  const size = file?.size;
  if (!Number.isSafeInteger(size) || size < 0 || size > maximumBytes) {
    throw new TypeError('Invalid file size');
  }
  return size;
}

function staleSessionError() {
  const error = new Error('Wallet session ended');
  error.code = 'STALE_SESSION';
  return error;
}

export function wipeSessionBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) return;
  try { intrinsicFill.call(bytes, 0); } catch { /* detached bytes are already unusable */ }
}

export function stopMediaStream(stream) {
  let tracks = [];
  try { tracks = stream?.getTracks?.() ?? []; } catch { /* malformed stream has no usable tracks */ }
  for (const track of tracks) {
    try { track?.stop?.(); } catch { /* continue stopping every remaining track */ }
  }
}

export async function readFileBytesForSession(file, { isCurrent, sessionGeneration }) {
  const declaredSize = exactBoundedFileSize(file, MAX_PHOTO_FILE_BYTES);
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (bytes.byteLength !== declaredSize || bytes.byteLength > MAX_PHOTO_FILE_BYTES) {
    wipeSessionBytes(bytes);
    throw new TypeError('Invalid file size');
  }
  if (!isCurrent(sessionGeneration)) {
    wipeSessionBytes(bytes);
    return null;
  }
  return bytes;
}

export function readTextFileForSession(file, {
  FileReader: FileReaderConstructor = globalThis.FileReader,
  isCurrent,
  maximumBytes,
  sessionGeneration,
  signal = null,
}) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
    return Promise.reject(new TypeError('Invalid file size limit'));
  }
  try {
    exactBoundedFileSize(file, maximumBytes);
  } catch (error) {
    return Promise.reject(error);
  }
  if (signal?.aborted === true || !isCurrent(sessionGeneration)) {
    return Promise.reject(staleSessionError());
  }
  if (typeof FileReaderConstructor !== 'function') {
    return Promise.reject(new TypeError('FileReader unavailable'));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReaderConstructor();
    let settled = false;
    const cleanup = () => {
      signal?.removeEventListener?.('abort', onAbort);
      reader.onload = null;
      reader.onerror = null;
      reader.onabort = null;
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onAbort = () => {
      if (settled) return;
      try { reader.abort?.(); } catch { /* stale callbacks remain settlement-guarded */ }
      finish(reject, staleSessionError());
    };
    reader.onload = () => {
      if (!isCurrent(sessionGeneration)) {
        finish(reject, staleSessionError());
        return;
      }
      if (typeof reader.result !== 'string' || reader.result.length > maximumBytes) {
        finish(reject, new TypeError('Invalid file size'));
        return;
      }
      finish(resolve, reader.result);
    };
    reader.onerror = () => finish(
      reject,
      isCurrent(sessionGeneration) ? new Error('Failed to read file') : staleSessionError(),
    );
    reader.onabort = () => finish(reject, staleSessionError());
    signal?.addEventListener?.('abort', onAbort, { once: true });
    if (signal?.aborted === true) {
      onAbort();
      return;
    }
    try {
      reader.readAsText(file);
    } catch (error) {
      finish(reject, error);
    }
  });
}

export async function acquireMediaStreamForSession(
  mediaDevices,
  constraints,
  { isCurrent, sessionGeneration },
) {
  const stream = await mediaDevices.getUserMedia(constraints);
  if (!isCurrent(sessionGeneration)) {
    stopMediaStream(stream);
    return null;
  }
  return stream;
}
