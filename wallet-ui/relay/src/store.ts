import { createRequire } from 'node:module';

import { constantTimeEqual } from './json.js';
import type { RegistryBinding } from './registry.js';

const require = createRequire(import.meta.url);

interface Statement {
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
  run(...parameters: unknown[]): { changes: number };
}

interface ImmediateTransaction<T> {
  (): T;
  immediate(): T;
}

interface DatabaseConnection {
  close(): void;
  exec(sql: string): void;
  pragma(source: string): unknown;
  prepare(sql: string): Statement;
  transaction<T>(operation: () => T): ImmediateTransaction<T>;
}

interface DatabaseConstructor {
  new(pathname: string): DatabaseConnection;
}

const Database = require('better-sqlite3') as DatabaseConstructor;

export type RelayStatus = 'pending' | 'completed' | 'consumed' | 'cancelled' | 'expired';

export interface StoredTransaction {
  readonly authorizationCode: string | null;
  readonly callbackUri: string;
  readonly clientDisplayName: string;
  readonly clientId: string;
  readonly codeChallenge: string;
  readonly expiresAtMs: number;
  readonly operation: string;
  readonly registryVersion: string;
  readonly requestJson: string | null;
  readonly requestOrigin: string;
  readonly requestSha256: string;
  readonly resultJson: string | null;
  readonly resultSha256: string | null;
  readonly resultToken: string | null;
  readonly state: string;
  readonly status: RelayStatus;
  readonly transactionId: string;
}

interface RawTransaction {
  authorization_code: string | null;
  callback_uri: string;
  client_display_name: string;
  client_id: string;
  code_challenge: string;
  expires_at_ms: number;
  operation: string;
  registry_version: string;
  request_json: string | null;
  request_origin: string;
  request_sha256: string;
  result_json: string | null;
  result_sha256: string | null;
  result_token: string | null;
  state: string;
  status: RelayStatus;
  transaction_id: string;
}

export type StoreOutcome<T = never> =
  | { readonly kind: 'ok'; readonly value: T }
  | { readonly kind: 'not-found' }
  | { readonly kind: 'conflict' }
  | { readonly kind: 'gone' }
  | { readonly kind: 'invalid-binding' }
  | { readonly kind: 'unregistered' }
  | { readonly kind: 'full' };

function mapRow(raw: RawTransaction): StoredTransaction {
  return {
    authorizationCode: raw.authorization_code,
    callbackUri: raw.callback_uri,
    clientDisplayName: raw.client_display_name,
    clientId: raw.client_id,
    codeChallenge: raw.code_challenge,
    expiresAtMs: raw.expires_at_ms,
    operation: raw.operation,
    registryVersion: raw.registry_version,
    requestJson: raw.request_json,
    requestOrigin: raw.request_origin,
    requestSha256: raw.request_sha256,
    resultJson: raw.result_json,
    resultSha256: raw.result_sha256,
    resultToken: raw.result_token,
    state: raw.state,
    status: raw.status,
    transactionId: raw.transaction_id,
  };
}

export class RelayStore {
  readonly #database: DatabaseConnection;
  readonly #maximumRows: number;
  readonly #observeSelect: (() => void) | undefined;
  #closed = false;

  constructor(databasePath: string, maximumRows = 4096, observeSelect?: () => void) {
    if (!Number.isSafeInteger(maximumRows) || maximumRows < 1 || maximumRows > 100_000) {
      throw new TypeError('maximumRows is invalid');
    }
    this.#maximumRows = maximumRows;
    this.#observeSelect = observeSelect;
    this.#database = new Database(databasePath);
    this.#database.pragma('journal_mode = WAL');
    this.#database.pragma('synchronous = FULL');
    this.#database.pragma('busy_timeout = 5000');
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS relay_transactions (
        transaction_id TEXT PRIMARY KEY NOT NULL,
        state TEXT NOT NULL,
        request_origin TEXT NOT NULL,
        client_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        registry_version TEXT NOT NULL,
        callback_uri TEXT NOT NULL,
        client_display_name TEXT NOT NULL,
        request_json TEXT,
        request_sha256 TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        result_token TEXT UNIQUE,
        result_json TEXT,
        result_sha256 TEXT,
        authorization_code TEXT UNIQUE,
        status TEXT NOT NULL CHECK (status IN ('pending','completed','consumed','cancelled','expired')),
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS relay_transactions_expiry
        ON relay_transactions(expires_at_ms, status);
    `);
    // A process start is a new boot generation. Nothing survives a restart.
    this.#database.exec('BEGIN IMMEDIATE; DELETE FROM relay_transactions; COMMIT;');
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #immediate<T>(operation: () => T): T {
    return this.#database.transaction(operation).immediate();
  }

  #raw(transactionId: string): RawTransaction | undefined {
    return this.#select('SELECT * FROM relay_transactions WHERE transaction_id = ?')
      .get(transactionId) as RawTransaction | undefined;
  }

  #select(sql: string): Statement {
    this.#observeSelect?.();
    return this.#database.prepare(sql);
  }

  #expireAll(nowMs: number): void {
    this.#database.prepare(`
      UPDATE relay_transactions
         SET request_json = NULL,
             result_json = NULL,
             result_token = NULL,
             authorization_code = NULL,
             status = 'expired'
       WHERE expires_at_ms <= ? AND status IN ('pending','completed')
    `).run(nowMs);
  }

  expire(nowMs: number): void {
    this.#immediate(() => this.#expireAll(nowMs));
  }

  create(input: {
    binding: RegistryBinding;
    codeChallenge: string;
    createdAtMs: number;
    expiresAtMs: number;
    requestJson: string;
    requestSha256: string;
    resultToken: string;
    state: string;
    transactionId: string;
  }): StoreOutcome<StoredTransaction> {
    return this.#immediate(() => {
      this.#expireAll(input.createdAtMs);
      if (this.#raw(input.transactionId)) return { kind: 'conflict' };
      let count = this.#select('SELECT COUNT(*) AS count FROM relay_transactions')
        .get() as { count: number };
      if (count.count >= this.#maximumRows) {
        this.#database.prepare(`
          DELETE FROM relay_transactions
           WHERE expires_at_ms <= ? AND status IN ('consumed','cancelled','expired')
        `).run(input.createdAtMs);
        count = this.#select('SELECT COUNT(*) AS count FROM relay_transactions')
          .get() as { count: number };
      }
      if (count.count >= this.#maximumRows) return { kind: 'full' };
      this.#database.prepare(`
        INSERT INTO relay_transactions (
          transaction_id, state, request_origin, client_id, operation,
          registry_version, callback_uri, client_display_name, request_json,
          request_sha256, code_challenge, result_token, result_json,
          result_sha256, authorization_code, status, created_at_ms, expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'pending', ?, ?)
      `).run(
        input.transactionId,
        input.state,
        input.binding.requestOrigin,
        input.binding.clientId,
        input.binding.operation,
        input.binding.registryReleaseSha256,
        input.binding.callbackUri,
        input.binding.clientDisplayName,
        input.requestJson,
        input.requestSha256,
        input.codeChallenge,
        input.resultToken,
        input.createdAtMs,
        input.expiresAtMs,
      );
      return { kind: 'ok', value: mapRow(this.#raw(input.transactionId) as RawTransaction) };
    });
  }

  get(transactionId: string, nowMs: number): StoreOutcome<StoredTransaction> {
    return this.#immediate(() => {
      this.#expireAll(nowMs);
      const row = this.#raw(transactionId);
      if (!row) return { kind: 'not-found' };
      if (row.status === 'expired' || row.status === 'cancelled') return { kind: 'gone' };
      if (row.status !== 'pending') return { kind: 'conflict' };
      return { kind: 'ok', value: mapRow(row) };
    });
  }

  peek(transactionId: string): StoredTransaction | undefined {
    const row = this.#raw(transactionId);
    return row ? mapRow(row) : undefined;
  }

  complete(input: {
    createAuthorizationCode: () => string;
    nowMs: number;
    resultJson: string;
    resultSha256: string;
    resultToken: string;
    transactionId: string;
  }): StoreOutcome<StoredTransaction> {
    return this.#immediate(() => {
      this.#expireAll(input.nowMs);
      const row = this.#raw(input.transactionId);
      if (!row) return { kind: 'not-found' };
      if (row.status === 'expired' || row.status === 'cancelled') return { kind: 'gone' };
      if (row.status !== 'pending') return { kind: 'conflict' };
      if (row.result_token === null || !constantTimeEqual(row.result_token, input.resultToken)) {
        return { kind: 'invalid-binding' };
      }
      const authorizationCode = input.createAuthorizationCode();
      const changed = this.#database.prepare(`
        UPDATE relay_transactions
           SET result_json = ?, result_sha256 = ?, authorization_code = ?, status = 'completed'
         WHERE transaction_id = ? AND status = 'pending'
      `).run(input.resultJson, input.resultSha256, authorizationCode, input.transactionId);
      if (changed.changes !== 1) return { kind: 'conflict' };
      return { kind: 'ok', value: mapRow(this.#raw(input.transactionId) as RawTransaction) };
    });
  }

  redeem(input: {
    code: string;
    codeChallenge: string;
    nowMs: number;
    requestOrigin: string;
    state: string;
    transactionId: string;
  }): StoreOutcome<{ resultJson: string; transaction: StoredTransaction }> {
    return this.#immediate(() => {
      this.#expireAll(input.nowMs);
      let row = this.#raw(input.transactionId);
      if (!row) {
        row = this.#select('SELECT * FROM relay_transactions WHERE authorization_code = ?')
          .get(input.code) as RawTransaction | undefined;
        if (row) return { kind: 'invalid-binding' };
        return { kind: 'not-found' };
      }
      if (row.status === 'expired' || row.status === 'cancelled') return { kind: 'gone' };
      if (row.status === 'consumed') return { kind: 'conflict' };
      if (row.status !== 'completed' || row.result_json === null || row.authorization_code === null) {
        return { kind: 'conflict' };
      }
      if (row.request_origin !== input.requestOrigin) return { kind: 'unregistered' };
      if (!constantTimeEqual(row.transaction_id, input.transactionId)
          || !constantTimeEqual(row.state, input.state)
          || !constantTimeEqual(row.authorization_code, input.code)
          || !constantTimeEqual(row.code_challenge, input.codeChallenge)) {
        return { kind: 'invalid-binding' };
      }
      const resultJson = row.result_json;
      const transaction = mapRow(row);
      const changed = this.#database.prepare(`
        UPDATE relay_transactions
           SET request_json = NULL,
               result_json = NULL,
               result_token = NULL,
               authorization_code = NULL,
               status = 'consumed'
         WHERE transaction_id = ? AND status = 'completed'
      `).run(input.transactionId);
      if (changed.changes !== 1) return { kind: 'conflict' };
      return { kind: 'ok', value: { resultJson, transaction } };
    });
  }

  cancel(input: {
    bodyTransactionId: string;
    codeChallenge: string;
    nowMs: number;
    pathTransactionId: string;
    requestOrigin: string;
    state: string;
  }): StoreOutcome<StoredTransaction> {
    return this.#immediate(() => {
      this.#expireAll(input.nowMs);
      const row = this.#raw(input.pathTransactionId);
      if (!row) return { kind: 'not-found' };
      if (row.status === 'expired' || row.status === 'cancelled') return { kind: 'gone' };
      if (row.status !== 'pending' && row.status !== 'completed') return { kind: 'conflict' };
      if (row.request_origin !== input.requestOrigin) return { kind: 'unregistered' };
      if (!constantTimeEqual(row.transaction_id, input.bodyTransactionId)
          || !constantTimeEqual(row.state, input.state)
          || !constantTimeEqual(row.code_challenge, input.codeChallenge)) {
        return { kind: 'invalid-binding' };
      }
      const transaction = mapRow(row);
      const changed = this.#database.prepare(`
        UPDATE relay_transactions
           SET request_json = NULL,
               result_json = NULL,
               result_token = NULL,
               authorization_code = NULL,
               status = 'cancelled'
         WHERE transaction_id = ? AND status IN ('pending','completed')
      `).run(input.pathTransactionId);
      if (changed.changes !== 1) return { kind: 'conflict' };
      return { kind: 'ok', value: transaction };
    });
  }
}
