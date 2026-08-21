function assertSynchronousOperation(operation) {
  if (typeof operation !== 'function') {
    throw new TypeError('Derived key operation must be a function');
  }
  if (operation.constructor?.name === 'AsyncFunction') {
    throw new TypeError('Derived key operation must be synchronous');
  }
}

function returnSynchronous(result) {
  if (result && typeof result.then === 'function') {
    throw new TypeError('Derived key operation must be synchronous');
  }
  return result;
}

/**
 * Keep a native derived-key handle inside one synchronous operation.
 * An accepted handle is always wiped, including when the operation throws.
 */
export function withDerivedHandle(deriveHandle, operation) {
  assertSynchronousOperation(operation);
  let derived;
  let accepted = false;
  try {
    derived = deriveHandle();
    if (!derived || typeof derived.wipe !== 'function') {
      throw new TypeError('Derived key handle must provide a callable wipe method');
    }
    accepted = true;
    return returnSynchronous(operation(derived));
  } finally {
    if (accepted) derived.wipe();
  }
}

/**
 * Keep mutable private-key bytes inside one synchronous operation.
 * Bytes are zeroed before the native handle is wiped on every exit path.
 */
export function withDerivedPrivateKey(deriveHandle, operation) {
  assertSynchronousOperation(operation);
  return withDerivedHandle(deriveHandle, (derived) => {
    let privateKey;
    try {
      privateKey = derived.privateKey();
      if (!(privateKey instanceof Uint8Array)) {
        throw new TypeError('Derived private key must be a Uint8Array');
      }
      return returnSynchronous(operation(privateKey));
    } finally {
      if (privateKey instanceof Uint8Array) privateKey.fill(0);
    }
  });
}
