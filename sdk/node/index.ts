/**
 * Ethio-Cyber-Shield (ECS) — Canonical Node.js / TypeScript SDK Client.
 * Provides HMAC-SHA256 signature calculation, nonces, and Canonical Event v1.1 telemetry helpers.
 */
import * as crypto from 'crypto';

export interface CanonicalEvent {
  event_id?: string;
  event_type: string;
  occurred_at?: string;
  source_system: string;
  user_id_pub?: string;
  account_id_pub?: string;
  session_id_pub?: string;
  device_id_pub?: string;
  source_ip?: string;
  endpoint?: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED' | 'HELD' | 'CHALLENGE_REQUIRED';
  amount_minor?: number;
  currency?: string;
  beneficiary_id_pub?: string;
  transaction_id_pub?: string;
  channel?: 'web' | 'mobile' | 'ussd' | 'api' | 'agent' | 'branch' | 'atm' | 'pos' | 'system';
  payment_rail?: 'p2p' | 'card' | 'wallet' | 'bill_pay' | 'interbank' | 'rtgs' | 'ach';
  counterparty_ref_hash?: string;
  device_fingerprint?: string;
  msisdn_hash?: string;
  agent_id?: string;
  national_id_hash?: string;
  locale_tz?: string;
  attributes?: Record<string, any>;
}

export function hashIdentifier(value?: string, salt?: string): string | undefined {
  if (!value) return undefined;
  const val = value.trim();
  if (!val) return undefined;
  const toHash = salt ? `${salt}:${val}` : val;
  return crypto.createHash('sha256').update(toHash, 'utf-8').digest('hex');
}

export function hashPhone(phone: string, salt?: string): string | undefined {
  if (!phone) return undefined;
  let digits = phone.replace(/[^0-9+]/g, '').trim();
  if (digits.startsWith('09') && digits.length === 10) {
    digits = '+251' + digits.slice(1);
  } else if (digits.startsWith('9') && digits.length === 9) {
    digits = '+251' + digits;
  } else if (digits.startsWith('251') && digits.length === 12) {
    digits = '+' + digits;
  }
  return hashIdentifier(digits, salt);
}

export function hashNationalId(id: string, salt?: string): string | undefined {
  return hashIdentifier(id, salt);
}

export function hashCounterparty(accountRef: string, salt?: string): string | undefined {
  return hashIdentifier(accountRef, salt);
}


export interface ECSClientOptions {
  ecsUrl: string;
  keyId: string;
  secretKey: string;
  organizationId?: string;
  timeoutMs?: number;
}

export class ECSClient {
  private ecsUrl: string;
  private keyId: string;
  private secretKey: string;
  private organizationId?: string;
  private timeoutMs: number;

  constructor(options: ECSClientOptions) {
    this.ecsUrl = options.ecsUrl.replace(/\/+$/, '');
    this.keyId = options.keyId;
    this.secretKey = options.secretKey;
    this.organizationId = options.organizationId;
    this.timeoutMs = options.timeoutMs || 10000;
  }

  public generateHeaders(method: string, pathWithQuery: string, rawBody: string = ''): Record<string, string> {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const bodySha256 = crypto.createHash('sha256').update(rawBody, 'utf-8').digest('hex');
    const canonicalString = `${timestamp}\n${nonce}\n${method.toUpperCase()}\n${pathWithQuery}\n${bodySha256}`;
    const signature = crypto.createHmac('sha256', this.secretKey).update(canonicalString, 'utf-8').digest('hex');

    const headers: Record<string, string> = {
      'X-ECS-Key-Id': this.keyId,
      'X-ECS-Timestamp': timestamp,
      'X-ECS-Nonce': nonce,
      'X-ECS-Signature': signature,
      'Content-Type': 'application/json',
    };

    if (this.organizationId) {
      headers['X-ECS-Tenant'] = this.organizationId;
    }

    return headers;
  }

  public async sendEvents(events: CanonicalEvent[]): Promise<{ status: string; count?: number; error?: string }> {
    const enrichedEvents = events.map(e => ({
      ...e,
      event_id: e.event_id || `evt-${crypto.randomBytes(6).toString('hex')}`,
      occurred_at: e.occurred_at || new Date().toISOString(),
      currency: e.currency || 'ETB',
      channel: e.channel || 'web',
      attributes: e.attributes || {},
    }));

    const path = '/api/events';
    const rawBody = JSON.stringify({ events: enrichedEvents });
    const headers = this.generateHeaders('POST', path, rawBody);

    try {
      const response = await fetch(`${this.ecsUrl}${path}`, {
        method: 'POST',
        headers,
        body: rawBody,
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!response.ok) {
        const text = await response.text();
        return { status: 'error', error: `HTTP ${response.status}: ${text}` };
      }

      const data = await response.json();
      return { status: 'ok', count: data.count || enrichedEvents.length };
    } catch (err: any) {
      return { status: 'error', error: err.message || String(err) };
    }
  }
}

export * from './outbox';
export * from './middleware';

