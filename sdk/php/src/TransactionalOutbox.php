<?php

namespace EthioCyberShield;

use PDO;

/**
 * Ethio-Cyber-Shield (ECS) — PHP Transactional Outbox.
 * Supports SQLite-backed persistent outbox and exponential retry dispatching.
 */
class TransactionalOutbox
{
    private ECSClient $client;
    private PDO $pdo;
    private float $initialBackoffSec;
    private float $maxBackoffSec;
    private int $maxAttempts;
    private int $batchSize;

    public function __construct(
        ECSClient $client,
        ?string $sqlitePath = null,
        float $initialBackoffSec = 2.0,
        float $maxBackoffSec = 300.0,
        int $maxAttempts = 8,
        int $batchSize = 50
    ) {
        $this->client = $client;
        $this->initialBackoffSec = $initialBackoffSec;
        $this->maxBackoffSec = $maxBackoffSec;
        $this->maxAttempts = $maxAttempts;
        $this->batchSize = $batchSize;

        $dbPath = $sqlitePath ?: sys_get_temp_dir() . '/ecs_outbox.sqlite';
        $this->pdo = new PDO("sqlite:{$dbPath}");
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->initDb();
    }

    private function initDb(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS ecs_outbox (
                event_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                next_retry_at REAL NOT NULL DEFAULT 0.0,
                delivered_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_ecs_outbox_queue ON ecs_outbox(status, next_retry_at);
        ");
    }

    public function enqueue(array $event): string
    {
        $eventId = $event['event_id'] ?? ('evt-' . bin2hex(random_bytes(6)));
        $event['event_id'] = $eventId;
        if (!isset($event['occurred_at'])) {
            $event['occurred_at'] = gmdate('c');
        }

        $now = microtime(true);
        $stmt = $this->pdo->prepare("
            INSERT INTO ecs_outbox (event_id, payload, status, attempts, created_at, updated_at, next_retry_at)
            VALUES (:id, :payload, 'PENDING', 0, :created, :updated, 0.0)
            ON CONFLICT(event_id) DO UPDATE SET payload = :payload_update, updated_at = :updated_update
        ");
        $json = json_encode($event);
        $stmt->execute([
            ':id' => $eventId,
            ':payload' => $json,
            ':created' => $now,
            ':updated' => $now,
            ':payload_update' => $json,
            ':updated_update' => $now,
        ]);

        return $eventId;
    }

    public function flush(): array
    {
        $now = microtime(true);
        $stmt = $this->pdo->prepare("
            SELECT event_id, payload, attempts
            FROM ecs_outbox
            WHERE status IN ('PENDING', 'FAILED') AND next_retry_at <= :now
            ORDER BY updated_at ASC
            LIMIT :limit
        ");
        $stmt->bindValue(':now', $now);
        $stmt->bindValue(':limit', $this->batchSize, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($rows)) {
            return ['processed' => 0, 'delivered' => 0, 'failed' => 0];
        }

        $events = array_map(fn($r) => json_decode($r['payload'], true), $rows);
        $res = $this->client->sendBatch($events);
        $delivered = 0;
        $failed = 0;

        if (isset($res['status']) && in_array($res['status'], ['ok', 'received'])) {
            $updateStmt = $this->pdo->prepare("
                UPDATE ecs_outbox SET status = 'DELIVERED', delivered_at = :now, updated_at = :now, last_error = NULL
                WHERE event_id = :id
            ");
            foreach ($rows as $row) {
                $updateStmt->execute([':now' => $now, ':id' => $row['event_id']]);
                $delivered++;
            }
        } else {
            $errorMsg = $res['message'] ?? 'Delivery failed';
            foreach ($rows as $row) {
                $attempts = (int)$row['attempts'] + 1;
                if ($attempts >= $this->maxAttempts) {
                    $deadStmt = $this->pdo->prepare("
                        UPDATE ecs_outbox SET status = 'DEAD_LETTER', attempts = :att, last_error = :err, updated_at = :now
                        WHERE event_id = :id
                    ");
                    $deadStmt->execute([':att' => $attempts, ':err' => $errorMsg, ':now' => $now, ':id' => $row['event_id']]);
                } else {
                    $backoff = min($this->maxBackoffSec, $this->initialBackoffSec * pow(2, $attempts - 1));
                    $failStmt = $this->pdo->prepare("
                        UPDATE ecs_outbox SET status = 'FAILED', attempts = :att, last_error = :err, next_retry_at = :retry, updated_at = :now
                        WHERE event_id = :id
                    ");
                    $failStmt->execute([':att' => $attempts, ':err' => $errorMsg, ':retry' => $now + $backoff, ':now' => $now, ':id' => $row['event_id']]);
                }
                $failed++;
            }
        }

        return ['processed' => count($rows), 'delivered' => $delivered, 'failed' => $failed];
    }
}
