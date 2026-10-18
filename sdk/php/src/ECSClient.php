<?php

namespace EthioCyberShield;

/**
 * Ethio-Cyber-Shield (ECS) — Canonical PHP SDK Client.
 * Provides HMAC-SHA256 signature generation, nonces, and Canonical Event v1.1 telemetry transmission.
 */
class ECSClient
{
    private string $ecsUrl;
    private string $keyId;
    private string $secretKey;
    private ?string $organizationId;
    private int $timeoutSeconds;

    public function __construct(
        string $ecsUrl,
        string $keyId,
        string $secretKey,
        ?string $organizationId = null,
        int $timeoutSeconds = 10
    ) {
        $this->ecsUrl = rtrim($ecsUrl, '/');
        $this->keyId = $keyId;
        $this->secretKey = $secretKey;
        $this->organizationId = $organizationId;
        $this->timeoutSeconds = $timeoutSeconds;
    }

    public function generateHeaders(string $method, string $path, string $rawBody = ''): array
    {
        $timestamp = (string) time();
        $nonce = sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );

        $bodySha256 = hash('sha256', $rawBody);
        $canonical = "{$timestamp}\n{$nonce}\n" . strtoupper($method) . "\n{$path}\n{$bodySha256}";
        $signature = hash_hmac('sha256', $canonical, $this->secretKey);

        $headers = [
            'Content-Type: application/json',
            "X-ECS-Key-Id: {$this->keyId}",
            "X-ECS-Timestamp: {$timestamp}",
            "X-ECS-Nonce: {$nonce}",
            "X-ECS-Signature: {$signature}",
        ];

        if ($this->organizationId) {
            $headers[] = "X-ECS-Tenant: {$this->organizationId}";
        }

        return $headers;
    }

    public function sendEvent(array $event): array
    {
        return $this->sendBatch([$event]);
    }

    public function sendBatch(array $events): array
    {
        $path = '/api/events';
        $url = $this->ecsUrl . $path;
        $payload = json_encode(['events' => $events]);
        $headers = $this->generateHeaders('POST', $path, $payload);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeoutSeconds);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return ['status' => 'error', 'message' => $curlError];
        }

        if ($httpCode >= 200 && $httpCode < 300) {
            $decoded = json_decode($response, true);
            return $decoded ?: ['status' => 'ok', 'count' => count($events)];
        }

        return ['status' => 'error', 'code' => $httpCode, 'message' => $response];
    }

    public static function hashIdentifier(?string $value, string $salt = ''): ?string
    {
        if ($value === null) return null;
        $val = trim($value);
        if ($val === '') return null;
        return hash('sha256', $salt ? "{$salt}:{$val}" : $val);
    }

    public static function hashPhone(string $phone, string $salt = ''): ?string
    {
        $digits = preg_replace('/[^0-9+]/', '', trim($phone));
        if (str_starts_with($digits, '09') && strlen($digits) === 10) {
            $digits = '+251' . substr($digits, 1);
        } elseif (str_starts_with($digits, '9') && strlen($digits) === 9) {
            $digits = '+251' . $digits;
        }
        return self::hashIdentifier($digits, $salt);
    }
}
