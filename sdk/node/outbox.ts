/**
 * Ethio-Cyber-Shield (ECS) — Canonical Node.js / TypeScript Transactional Outbox.
 * Generalizes ShieldBank's outbox.server.ts into an independent enterprise client pattern.
 * Provides at-least-once telemetry delivery, exponential backoff, dead-letter handling,
 * and background dispatching.
 */
import * as crypto from 'crypto';
import { CanonicalEvent, ECSClient } from './index';

export interface OutboxItem {
  event_id: string;
  payload: CanonicalEvent;
  status: 'PENDING' | 'DELIVERED' | 'FAILED' | 'DEAD_LETTER';
  attempts: number;
  last_error?: string;
  created_at: number;
  updated_at: number;
  next_retry_at: number;
  delivered_at?: number;
}

export interface IOutboxStorage {
  save(eventId: string, payload: CanonicalEvent): Promise<void> | void;
  getById(eventId: string): Promise<OutboxItem | undefined> | OutboxItem | undefined;
  getPendingAndRetryable(limit: number, now: number): Promise<OutboxItem[]> | OutboxItem[];
  markDelivered(eventId: string): Promise<void> | void;
  markFailed(eventId: string, attempts: number, error: string, nextRetryAt: number): Promise<void> | void;
  markDeadLetter(eventId: string, attempts: number, error: string): Promise<void> | void;
  getStats(): Promise<Record<string, number>> | Record<string, number>;
}

export class InMemoryOutboxStorage implements IOutboxStorage {
  private items = new Map<string, OutboxItem>();

  public save(eventId: string, payload: CanonicalEvent): void {
    const now = Date.now() / 1000;
    this.items.set(eventId, {
      event_id: eventId,
      payload,
      status: 'PENDING',
      attempts: 0,
      created_at: now,
      updated_at: now,
      next_retry_at: 0,
    });
  }

  public getById(eventId: string): OutboxItem | undefined {
    return this.items.get(eventId);
  }

  public getPendingAndRetryable(limit: number, now: number): OutboxItem[] {
    const results: OutboxItem[] = [];
    for (const item of this.items.values()) {
      if ((item.status === 'PENDING' || item.status === 'FAILED') && item.next_retry_at <= now) {
        results.push(item);
      }
    }
    results.sort((a, b) => a.updated_at - b.updated_at);
    return results.slice(0, limit);
  }

  public markDelivered(eventId: string): void {
    const item = this.items.get(eventId);
    if (item) {
      item.status = 'DELIVERED';
      item.delivered_at = Date.now() / 1000;
      item.last_error = undefined;
      item.updated_at = Date.now() / 1000;
    }
  }

  public markFailed(eventId: string, attempts: number, error: string, nextRetryAt: number): void {
    const item = this.items.get(eventId);
    if (item) {
      item.status = 'FAILED';
      item.attempts = attempts;
      item.last_error = error;
      item.next_retry_at = nextRetryAt;
      item.updated_at = Date.now() / 1000;
    }
  }

  public markDeadLetter(eventId: string, attempts: number, error: string): void {
    const item = this.items.get(eventId);
    if (item) {
      item.status = 'DEAD_LETTER';
      item.attempts = attempts;
      item.last_error = error;
      item.updated_at = Date.now() / 1000;
    }
  }

  public getStats(): Record<string, number> {
    const stats: Record<string, number> = { PENDING: 0, DELIVERED: 0, FAILED: 0, DEAD_LETTER: 0 };
    for (const item of this.items.values()) {
      stats[item.status] = (stats[item.status] || 0) + 1;
    }
    return stats;
  }
}

export interface TransactionalOutboxOptions {
  client: ECSClient;
  storage?: IOutboxStorage;
  initialBackoffSec?: number;
  maxBackoffSec?: number;
  maxAttempts?: number;
  batchSize?: number;
}

export class TransactionalOutbox {
  private client: ECSClient;
  private storage: IOutboxStorage;
  private initialBackoffSec: number;
  private maxBackoffSec: number;
  private maxAttempts: number;
  private batchSize: number;
  private timer: NodeJS.Timeout | null = null;
  private isFlushing = false;

  constructor(options: TransactionalOutboxOptions) {
    this.client = options.client;
    this.storage = options.storage || new InMemoryOutboxStorage();
    this.initialBackoffSec = options.initialBackoffSec || 2.0;
    this.maxBackoffSec = options.maxBackoffSec || 300.0;
    this.maxAttempts = options.maxAttempts || 8;
    this.batchSize = options.batchSize || 50;
  }

  public async enqueue(event: CanonicalEvent): Promise<string> {
    const eventId = event.event_id || `evt-${crypto.randomBytes(6).toString('hex')}`;
    const normalized: CanonicalEvent = {
      ...event,
      event_id: eventId,
      occurred_at: event.occurred_at || new Date().toISOString(),
      channel: event.channel || 'web',
      result: event.result || 'SUCCESS',
      attributes: event.attributes || {},
    };

    await this.storage.save(eventId, normalized);
    return eventId;
  }

  public async flush(): Promise<{ processed: number; delivered: number; failed: number }> {
    if (this.isFlushing) {
      return { processed: 0, delivered: 0, failed: 0 };
    }
    this.isFlushing = true;

    try {
      const now = Date.now() / 1000;
      const batch = await this.storage.getPendingAndRetryable(this.batchSize, now);

      if (!batch || batch.length === 0) {
        return { processed: 0, delivered: 0, failed: 0 };
      }

      const events = batch.map((item) => item.payload);
      let delivered = 0;
      let failed = 0;

      try {
        const resp = await this.client.sendEvents(events);
        if (resp.status === 'ok') {
          for (const item of batch) {
            await this.storage.markDelivered(item.event_id);
            delivered++;
          }
        } else {
          const errText = resp.error || 'Delivery failed with non-OK status';
          await this.handleBatchFailure(batch, errText, now);
          failed += batch.length;
        }
      } catch (err: any) {
        const errText = err?.message || String(err);
        await this.handleBatchFailure(batch, errText, now);
        failed += batch.length;
      }

      return { processed: batch.length, delivered, failed };
    } finally {
      this.isFlushing = false;
    }
  }

  private async handleBatchFailure(batch: OutboxItem[], errorMsg: string, now: number): Promise<void> {
    for (const item of batch) {
      const nextAttempt = item.attempts + 1;
      if (nextAttempt >= this.maxAttempts) {
        await this.storage.markDeadLetter(item.event_id, nextAttempt, errorMsg);
      } else {
        const backoff = Math.min(
          this.maxBackoffSec,
          this.initialBackoffSec * Math.pow(2, nextAttempt - 1)
        );
        await this.storage.markFailed(item.event_id, nextAttempt, errorMsg, now + backoff);
      }
    }
  }

  public startWorker(intervalMs: number = 5000): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.flush().catch(() => {});
    }, intervalMs);
    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  public stopWorker(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public isWorkerRunning(): boolean {
    return this.timer !== null;
  }

  public async getStats(): Promise<Record<string, number>> {
    return this.storage.getStats();
  }
}
