/**
 * Ethio-Cyber-Shield (ECS) — Express.js Telemetry Middleware.
 * Automatically captures auth, access-denied, and payment events into the Transactional Outbox.
 */
import { CanonicalEvent, ECSClient } from './index';
import { TransactionalOutbox } from './outbox';

export interface ECSExpressMiddlewareOptions {
  client: ECSClient;
  outbox?: TransactionalOutbox;
  sourceSystem?: string;
  authPaths?: string[];
  paymentPaths?: string[];
}

export function ecsExpressMiddleware(options: ECSExpressMiddlewareOptions) {
  const outbox = options.outbox || new TransactionalOutbox({ client: options.client });
  const sourceSystem = options.sourceSystem || 'express-app';
  const authPaths = options.authPaths || ['/login', '/api/login', '/api/auth/login', '/auth/signin'];
  const paymentPaths = options.paymentPaths || ['/transfer', '/api/transfer', '/pay', '/api/payment'];

  return function (req: any, res: any, next: () => void) {
    const startTime = Date.now();

    res.on('finish', () => {
      try {
        const path = req.baseUrl ? `${req.baseUrl}${req.path}` : req.path || req.url;
        const statusCode = res.statusCode;

        const isAuth = authPaths.some((p) => path.endsWith(p));
        const isPayment = paymentPaths.some((p) => path.endsWith(p));
        const isDenied = statusCode === 401 || statusCode === 403;

        if (!isAuth && !isPayment && !isDenied) {
          return;
        }

        let eventType = 'api.request';
        let result: 'SUCCESS' | 'FAILURE' | 'DENIED' = statusCode < 400 ? 'SUCCESS' : 'FAILURE';

        if (isAuth) {
          eventType = statusCode < 400 ? 'auth.login.succeeded' : 'auth.login.failed';
        } else if (isDenied) {
          eventType = 'authz.denied';
          result = 'DENIED';
        } else if (isPayment) {
          eventType = 'transaction.transfer.created';
        }

        const forwarded = req.headers['x-forwarded-for'];
        const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket?.remoteAddress;

        const event: CanonicalEvent = {
          event_type: eventType,
          result,
          source_system: sourceSystem,
          endpoint: path,
          source_ip: ip,
          channel: 'web',
          attributes: {
            http_method: req.method,
            http_status: statusCode,
            latency_ms: Date.now() - startTime,
            user_agent: req.headers['user-agent'] || 'unknown',
          },
        };

        void outbox.enqueue(event).catch(() => {});
      } catch {
        // Telemetry failure must never disrupt application traffic
      }
    });

    next();
  };
}
