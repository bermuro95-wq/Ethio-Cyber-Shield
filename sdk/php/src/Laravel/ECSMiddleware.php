<?php

namespace EthioCyberShield\Laravel;

use Closure;
use EthioCyberShield\TransactionalOutbox;

/**
 * Ethio-Cyber-Shield (ECS) — Laravel Telemetry Middleware.
 * Captures authentication and payment requests and sends them to the ECS Outbox.
 */
class ECSMiddleware
{
    protected TransactionalOutbox $outbox;

    public function __construct(TransactionalOutbox $outbox)
    {
        $this->outbox = $outbox;
    }

    public function handle($request, Closure $next)
    {
        $response = $next($request);

        try {
            $path = $request->path();
            $status = $response->getStatusCode();
            $isAuth = str_contains($path, 'login') || str_contains($path, 'auth');
            $isPayment = str_contains($path, 'transfer') || str_contains($path, 'pay');
            $isDenied = in_array($status, [401, 403]);

            if ($isAuth || $isPayment || $isDenied) {
                $result = $status < 400 ? 'SUCCESS' : ($status === 403 ? 'DENIED' : 'FAILURE');
                $eventType = $isAuth ? ($result === 'SUCCESS' ? 'auth.login.succeeded' : 'auth.login.failed') : 'api.request';

                $this->outbox->enqueue([
                    'event_type' => $eventType,
                    'result' => $result,
                    'source_system' => config('app.name', 'laravel-app'),
                    'endpoint' => '/' . ltrim($path, '/'),
                    'source_ip' => $request->ip(),
                    'channel' => 'web',
                    'attributes' => [
                        'http_method' => $request->method(),
                        'http_status' => $status,
                    ],
                ]);
            }
        } catch (\Throwable $e) {
            // Silently avoid impacting application lifecycle
        }

        return $response;
    }
}
