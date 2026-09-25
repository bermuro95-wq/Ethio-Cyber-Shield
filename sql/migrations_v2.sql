-- Ethio-Cyber Shield v2 migrations (safe to re-run)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Watchlists
CREATE TABLE IF NOT EXISTS watchlists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN ('account', 'device', 'ip', 'email', 'domain')),
    value TEXT NOT NULL,
    label VARCHAR(255),
    severity VARCHAR(50) NOT NULL DEFAULT 'high' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entity_type, value)
);

CREATE INDEX IF NOT EXISTS idx_watchlists_type_value ON watchlists(entity_type, value);
CREATE INDEX IF NOT EXISTS idx_watchlists_active ON watchlists(is_active);

-- Alert investigation notes
CREATE TABLE IF NOT EXISTS alert_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id);

-- System settings (rule thresholds etc.)
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}',
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO system_settings (key, value) VALUES
('fraud_rules', '{
  "high_amount": 500000,
  "critical_amount": 1500000,
  "night_amount": 200000,
  "burst_count": 4,
  "burst_window_minutes": 30,
  "velocity_amount": 800000,
  "new_device_amount": 200000,
  "multi_account_device": 3,
  "shared_ip_accounts": 4,
  "large_withdrawal": 300000,
  "rapid_transfer_amount": 150000,
  "rapid_window_minutes": 10
}'::jsonb)
ON CONFLICT (key) DO NOTHING;
