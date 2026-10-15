-- Ethio-Cyber Shield (ECS) v3 Migrations: Automated Target System Integration & Response Platform
-- Run this in Supabase SQL Editor or apply via migration runner

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =========================================================================
-- 1. TARGET SYSTEMS (Connected Applications Registry)
-- =========================================================================
CREATE TABLE IF NOT EXISTS target_systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    base_url TEXT NOT NULL,
    key_id VARCHAR(100) NOT NULL UNIQUE,
    secret_key TEXT NOT NULL,
    sync_mode VARCHAR(20) NOT NULL DEFAULT 'bidirectional' CHECK (sync_mode IN ('push', 'pull', 'bidirectional')),
    poll_interval_seconds INT DEFAULT 5,
    last_synced_seq BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    health_status VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_target_systems_key_id ON target_systems(key_id);
CREATE INDEX IF NOT EXISTS idx_target_systems_active ON target_systems(is_active);

-- =========================================================================
-- 2. SECURITY EVENTS (Telemetry v1.0 Common Envelope)
-- =========================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    event_id VARCHAR(100) UNIQUE NOT NULL,
    seq BIGINT,
    event_type VARCHAR(100) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    source_system VARCHAR(100) NOT NULL,
    user_id_pub VARCHAR(100),
    account_id_pub VARCHAR(100),
    session_id_pub VARCHAR(100),
    device_id_pub VARCHAR(100),
    source_ip VARCHAR(50),
    endpoint VARCHAR(255),
    result VARCHAR(50) NOT NULL,
    amount_minor BIGINT,
    currency VARCHAR(10),
    beneficiary_id_pub VARCHAR(100),
    transaction_id_pub VARCHAR(100),
    delivery_status VARCHAR(50) DEFAULT 'DELIVERED',
    attributes JSONB NOT NULL DEFAULT '{}',
    raw_payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events(event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_account ON security_events(account_id_pub);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id_pub);
CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at ON security_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_target ON security_events(target_system_id);

-- =========================================================================
-- 3. DETECTION RULES (Deterministic L1-L4 Detection Catalog)
-- =========================================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    layer VARCHAR(10) NOT NULL CHECK (layer IN ('L1', 'L2', 'L3', 'L4')),
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    weight INT DEFAULT 20,
    thresholds JSONB DEFAULT '{}',
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =========================================================================
-- 4. DETECTIONS (Rule Execution Findings)
-- =========================================================================
CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id VARCHAR(50) REFERENCES detection_rules(id),
    severity VARCHAR(50) NOT NULL,
    score_contribution INT DEFAULT 0,
    entity_type VARCHAR(50),
    entity_id VARCHAR(100),
    summary TEXT NOT NULL,
    evidence JSONB DEFAULT '{}',
    trigger_event_ids TEXT[],
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detections_entity ON detections(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id);

-- =========================================================================
-- 5. RISK ASSESSMENTS (Explainable 0-100 Score Records)
-- =========================================================================
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(100) NOT NULL,
    risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level VARCHAR(50) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    confidence VARCHAR(50) DEFAULT 'high',
    reasons TEXT[],
    breakdown JSONB DEFAULT '[]',
    trigger_event_ids TEXT[],
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    assessed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_entity ON risk_assessments(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_time ON risk_assessments(assessed_at DESC);

-- =========================================================================
-- 6. RESPONSE ACTIONS (Dispatched Mitigations Tracking)
-- =========================================================================
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_system_id UUID REFERENCES target_systems(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL CHECK (action_type IN ('freeze_transaction', 'revoke_session', 'block_ip', 'require_step_up', 'disable_beneficiary', 'lock_account', 'revert')),
    target_entity_type VARCHAR(50),
    target_entity_id VARCHAR(100),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'failed', 'reverted')),
    alert_id UUID REFERENCES alerts(id),
    incident_id UUID REFERENCES incidents(id),
    reason TEXT NOT NULL,
    requested_by UUID REFERENCES users(id),
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    target_response JSONB,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_actions_target ON response_actions(target_system_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_time ON response_actions(requested_at DESC);

-- =========================================================================
-- 7. API NONCES (Replay Prevention)
-- =========================================================================
CREATE TABLE IF NOT EXISTS api_nonces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(100) NOT NULL,
    nonce VARCHAR(100) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_nonces_nonce ON api_nonces(nonce);
CREATE INDEX IF NOT EXISTS idx_api_nonces_expires ON api_nonces(expires_at);

-- =========================================================================
-- 8. SCHEMA ENHANCEMENTS FOR EXISTING TABLES
-- =========================================================================
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS target_system_id UUID REFERENCES target_systems(id);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS raw_event_id VARCHAR(100);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS target_system_id UUID REFERENCES target_systems(id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '{}';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score INT DEFAULT 0;

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS target_system_id UUID REFERENCES target_systems(id);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '{}';

ALTER TABLE indicators ADD COLUMN IF NOT EXISTS target_system_id UUID REFERENCES target_systems(id);
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS confidence VARCHAR(50) DEFAULT 'high';

-- =========================================================================
-- 9. INITIAL SEED DATA: CANONICAL DETECTION RULES (§21)
-- =========================================================================
INSERT INTO detection_rules (id, name, description, category, layer, severity, weight, thresholds) VALUES
('AUTH-001', 'Login Failure Burst', 'Rapid failed password attempts on a single account identifier within 60 seconds.', 'authentication', 'L1', 'medium', 25, '{"burst_count": 5, "window_seconds": 60}'::jsonb),
('AUTH-002', 'Multi-Account Source Burst', 'Single source IP attempting credentials across multiple distinct account identifiers (credential stuffing).', 'authentication', 'L1', 'high', 35, '{"distinct_identifiers": 3, "window_seconds": 60}'::jsonb),
('AUTH-003', 'New Device After Suspicious Failures', 'Successful authentication from an unrecognized hardware device immediately following authentication failures.', 'authentication', 'L2', 'high', 35, '{"window_minutes": 5}'::jsonb),
('ATO-001', 'Account Takeover Chain (ATO)', 'Complete attack chain: failed logins -> successful login from new device -> beneficiary creation -> high-value transfer.', 'correlation', 'L3', 'critical', 80, '{"sequence_window_minutes": 15}'::jsonb),
('TX-001', 'High-Value Transfer Anomaly', 'Transfer amount exceeds configured risk threshold (e.g. >= 100,000 ETB).', 'transaction', 'L1', 'medium', 20, '{"amount_threshold_etb": 100000}'::jsonb),
('TX-002', 'Velocity Anomaly', 'Multiple transfers from the same account exceeding rate or cumulative volume within 30 minutes.', 'transaction', 'L2', 'high', 30, '{"burst_count": 4, "window_minutes": 30}'::jsonb),
('TX-003', 'Off-Hours High-Value Transfer', 'High-value transfer executed outside normal banking hours (00:00 to 05:00 Addis Ababa time).', 'transaction', 'L2', 'high', 25, '{"start_hour": 0, "end_hour": 5, "amount_threshold_etb": 100000}'::jsonb),
('TX-004', 'Untrusted Device Transfer', 'Transfer initiated from a device marked as untrusted or registered less than 1 hour ago.', 'transaction', 'L2', 'high', 25, '{"max_device_age_seconds": 3600}'::jsonb),
('IOC-001', 'Malicious Source IP Match', 'Activity originating from an IP address recorded in Threat Indicators or Watchlists with status malicious.', 'ioc', 'L1', 'high', 40, '{}'::jsonb),
('CORR-001', 'Shared Device Across Multiple Accounts', 'Same hardware client device fingerprint observed transacting across 3 or more distinct accounts in 48 hours.', 'correlation', 'L3', 'high', 35, '{"distinct_accounts": 3, "window_hours": 48}'::jsonb),
('API-001', 'Authorization Denial Burst', 'Session or client IP receiving repeated 403 Forbidden or AUTHZ_DENIED responses within a short interval.', 'api', 'L1', 'medium', 25, '{"denial_count": 4, "window_seconds": 60}'::jsonb),
('API-002', 'Sequential Resource Enumeration Probing', 'Rapid enumeration of sequential object IDs (IDOR probing) across banking endpoints.', 'api', 'L3', 'high', 35, '{"probe_window_seconds": 60}'::jsonb),
('PRIV-001', 'Unauthorized Privilege Abuse Attempt', 'Regular customer identity attempting access to administrative operations or security control endpoints.', 'privilege', 'L2', 'high', 40, '{}'::jsonb)
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    layer = EXCLUDED.layer,
    severity = EXCLUDED.severity,
    weight = EXCLUDED.weight,
    thresholds = EXCLUDED.thresholds;

-- =========================================================================
-- 10. INITIAL SEED DATA: DEFAULT TARGET SYSTEM (ShieldBank Testbed)
-- =========================================================================
INSERT INTO target_systems (id, name, base_url, key_id, secret_key, sync_mode, poll_interval_seconds, is_active, health_status) VALUES
('00000000-0000-0000-0000-000000000001', 'ShieldBank Core Testbed', 'http://127.0.0.1:3000', 'ecs_live_prod_key_01', 'super-secret-key-32b', 'bidirectional', 5, TRUE, 'healthy')
ON CONFLICT (key_id) DO UPDATE SET
    name = EXCLUDED.name,
    base_url = EXCLUDED.base_url,
    secret_key = EXCLUDED.secret_key,
    sync_mode = EXCLUDED.sync_mode;
