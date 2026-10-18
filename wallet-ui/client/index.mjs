import {
  buildFieldOpenRequest,
  buildFieldOpenResult,
  buildKeyUnwrapRequest,
  buildKeyUnwrapResult,
  buildWalletAccountRequest,
  buildWalletAccountResult,
  buildWalletConnectRequest,
  buildWalletConnectResult,
  decodeBase64urlBytes,
  fieldContextSite,
  FIELD_OPEN_LIMITS,
  parseFieldOpenRequest,
  parseKeyUnwrapRequest,
} from './wire.mjs';
import { createReplyKey } from './reply-cipher.mjs';
import {
  createInternalWalletClient,
  createPublicApi,
  walletClientError,
  WALLET_CLIENT_ERRORS,
} from './relay-client.mjs';

const CLIENT_IDS = Object.freeze([
  'orbpro-pages-v1',
  'sdn-asset-models-pages-v1',
  'sdn-asset-review-v1',
  'sdn-flatbuffers-pages-v1',
  'sdn-flatsql-pages-v1',
  'sdn-landing-web-v1',
  'sdn-module-sdk-pages-v1',
  'sdn-node-console-v1',
  'sdn-standards-web-v1',
  'spaceaware-web-v1',
]);

export { WALLET_CLIENT_ERRORS };

function validateWalletClientOptions(options) {
  let descriptor;
  try {
    const keys = Reflect.ownKeys(options);
    if (options === null || typeof options !== 'object' || Array.isArray(options)
        || Object.getPrototypeOf(options) !== Object.prototype
        || keys.length !== 1 || keys[0] !== 'clientId') {
      throw walletClientError('INVALID_REQUEST');
    }
    descriptor = Object.getOwnPropertyDescriptor(options, 'clientId');
  } catch {
    throw walletClientError('INVALID_REQUEST');
  }
  if (!descriptor?.enumerable || !('value' in descriptor)
      || typeof descriptor.value !== 'string') {
    throw walletClientError('INVALID_REQUEST');
  }
  if (!CLIENT_IDS.includes(descriptor.value)) throw walletClientError('INVALID_CLIENT');
  return descriptor.value;
}

const BASE_ADAPTERS = Object.freeze({
  account: Object.freeze({
    buildRequest: () => buildWalletAccountRequest({}),
    kind: 'account',
    operation: 'sdn.wallet.account.v1',
    parseResult: buildWalletAccountResult,
  }),
  connect: Object.freeze({
    buildRequest: () => buildWalletConnectRequest({}),
    kind: 'connect',
    operation: 'sdn.wallet.connect.v1',
    parseResult: buildWalletConnectResult,
  }),
});

function requireSite(context, site) {
  if (fieldContextSite(context) !== site) throw walletClientError('INVALID_REQUEST');
}

/**
 * The reply key is made after the popup opens (Web Crypto is asynchronous)
 * and before the request is hashed and registered; the opener it returns
 * turns the wallet's reply ciphertext back into bytes.
 */
function sealedAdapter({ operation, buildRequest, parseRequest, parseResult, openResult }) {
  return Object.freeze({
    buildRequest,
    kind: 'typed',
    operation,
    parseResult,
    async seal(request, cryptoObject) {
      let replyKey;
      try {
        replyKey = await createReplyKey(cryptoObject);
      } catch {
        throw walletClientError('CRYPTO_UNAVAILABLE');
      }
      return Object.freeze({
        request: parseRequest({ ...request, replyPublicKeyHex: replyKey.publicKeyHex }),
        async open(result) {
          const ciphertexts = result.fields.map((field) => (field.status === 'opened'
            ? decodeBase64urlBytes(field.ciphertextBase64url, 1, FIELD_OPEN_LIMITS.fieldBytes, 'reply')
            : null));
          let plaintexts;
          try {
            plaintexts = await replyKey.open(result.replyEphemeralPublicKeyHex, ciphertexts);
          } catch {
            throw walletClientError('CRYPTO_UNAVAILABLE');
          }
          return openResult(plaintexts);
        },
      });
    },
  });
}

/** Fields sealed to the user for this site, opened by the wallet. */
const fieldOpenAdapter = (site) => sealedAdapter({
  operation: 'sdn.wallet.field-open.v1',
  buildRequest(input) {
    const request = buildFieldOpenRequest(input);
    for (const field of request.fields) requireSite(field.context, site);
    return request;
  },
  parseRequest: parseFieldOpenRequest,
  parseResult: buildFieldOpenResult,
  openResult: (plaintexts) => Object.freeze(plaintexts.map((plaintext) => Object.freeze(plaintext === null
    ? { refused: 'NOT_ADDRESSED_TO_ACCOUNT' }
    : { plaintext }))),
});

/** A database content key wrapped to the user for this site, unwrapped by the wallet. */
const keyUnwrapAdapter = (site) => sealedAdapter({
  operation: 'sdn.wallet.key-unwrap.v1',
  buildRequest(input) {
    const request = buildKeyUnwrapRequest(input);
    requireSite(request.context, site);
    return request;
  },
  parseRequest: parseKeyUnwrapRequest,
  parseResult: buildKeyUnwrapResult,
  openResult([contentKey]) {
    if (contentKey === null) throw walletClientError('NOT_ADDRESSED_TO_ACCOUNT');
    if (contentKey.length !== 32) throw walletClientError('RELAY_ERROR');
    return Object.freeze({ contentKey });
  },
});

// Clients whose registry row lets the wallet open their sites' sealed data.
const SEALED_CLIENTS = Object.freeze({
  'sdn-flatbuffers-pages-v1': Object.freeze({ method: 'openFields', adapter: fieldOpenAdapter('flatbuffers') }),
  'sdn-flatsql-pages-v1': Object.freeze({ method: 'unwrapKey', adapter: keyUnwrapAdapter('flatsql') }),
});

export function createWalletClient(options) {
  if (arguments.length !== 1) throw walletClientError('INVALID_REQUEST');
  const clientId = validateWalletClientOptions(options);
  const sealed = SEALED_CLIENTS[clientId];
  if (!sealed) {
    const core = createInternalWalletClient({ adapters: BASE_ADAPTERS, clientId });
    return createPublicApi(core);
  }
  const core = createInternalWalletClient({
    adapters: Object.freeze({ ...BASE_ADAPTERS, sealed: sealed.adapter }),
    clientId,
  });
  return createPublicApi(core, { [sealed.method]: 'sealed' });
}
