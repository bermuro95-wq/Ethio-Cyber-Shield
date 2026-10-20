-- =========================================================================
-- Ethio-Cyber-Shield (ECS) v3.0 Independent Platform Database Schema
-- Multi-Tenant PostgreSQL Schema with Row-Level Security (RLS)
-- =========================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =========================================================================
-- 1. ORGANIZATIONS (Multi-Tenancy Foundation)
-- =========================================================================
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    sector VARCHAR(100) NOT NULL DEFAULT 'Finance - Commercial Bank',
    license_reference VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- =========================================================================
-- 2. USERS & ROLES
-- =========================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'analyst', 'responder', 'viewer', 'auditor')),
    mfa_secret VARCHAR(100),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- =========================================================================
-- 3. CONNECTED TARGET SYSTEMS
-- =========================================================================
CREATE TABLE IF NOT EXISTS target_systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    base_url TEXT NOT NULL,
    key_id VARCHAR(100) NOT NULL UNIQUE,
    secret_key TEXT NOT NULL,
    encrypted_secret_key BYTEA,
    sync_mode VARCHAR(20) NOT NULL DEFAULT 'bidirectional' CHECK (sync_mode IN ('push', 'pull', 'bidirectional')),
    poll_interval_seconds INT DEFAULT 5,
    last_synced_seq BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    health_status VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_target_systems_org ON target_systems(organization_id);
CREATE INDEX IF NOT EXISTS idx_target_systems_key_id ON target_systems(key_id);

-- =========================================================================
-- 3b. INBOUND WEBHOOK SOURCES & FIELD MAPPINGS
-- =========================================================================
CREATE TABLE IF NOT EXISTS webhook_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_id VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    secret_token TEXT,
    encrypted_secret_token BYTEA,
    auth_type VARCHAR(50) NOT NULL DEFAULT 'token' CHECK (auth_type IN ('token', 'hmac_sha256', 'none')),
    signature_header VARCHAR(100) DEFAULT 'X-Webhook-Secret',
    mapping_rules JSONB NOT NULL DEFAULT '{}',
    sample_payload JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    total_received BIGINT DEFAULT 0,
    last_received_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_sources_org ON webhook_sources(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhook_sources_source_id ON webhook_sources(source_id);

-- =========================================================================
-- 4. TELEMETRY & SECURITY EVENTS
-- =========================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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
    currency VARCHAR(10) DEFAULT 'ETB',
    beneficiary_id_pub VARCHAR(100),
    transaction_id_pub VARCHAR(100),
    channel VARCHAR(50) DEFAULT 'web',
    payment_rail VARCHAR(50),
    counterparty_ref_hash VARCHAR(64),
    device_fingerprint VARCHAR(128),
    msisdn_hash VARCHAR(64),
    agent_id VARCHAR(100),
    national_id_hash VARCHAR(64),
    locale_tz VARCHAR(64) DEFAULT 'Africa/Addis_Ababa',
    delivery_status VARCHAR(50) DEFAULT 'DELIVERED',
    attributes JSONB NOT NULL DEFAULT '{}',
    raw_payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_org ON security_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events(organization_id, event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(organization_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_account ON security_events(organization_id, account_id_pub);
CREATE INDEX IF NOT EXISTS idx_security_events_device ON security_events(organization_id, device_id_pub);
CREATE INDEX IF NOT EXISTS idx_security_events_channel ON security_events(organization_id, channel);
CREATE INDEX IF NOT EXISTS idx_security_events_msisdn ON security_events(organization_id, msisdn_hash);
CREATE INDEX IF NOT EXISTS idx_security_events_counterparty ON security_events(organization_id, counterparty_ref_hash);
CREATE INDEX IF NOT EXISTS idx_security_events_device_fp ON security_events(organization_id, device_fingerprint);

-- =========================================================================
-- 5. INCIDENTS (Statutory Readiness)
-- =========================================================================
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    incident_type VARCHAR(100) NOT NULL CHECK (incident_type IN (
        'phishing', 'account_takeover', 'suspicious_login', 'fraud', 
        'malware', 'social_engineering', 'api_abuse', 'other'
    )),
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    incident_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detection_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_to UUID REFERENCES users(id),
    risk_score INTEGER DEFAULT 0,
    risk_level VARCHAR(50) DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    risk_reasons TEXT[],
    evidence JSONB DEFAULT '{}',
    evidence_sha256 VARCHAR(64),
    is_reportable_48h BOOLEAN DEFAULT TRUE,
    reported_to_cert_at TIMESTAMPTZ,
    cert_reference_no VARCHAR(100),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_org_severity ON incidents(organization_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_detection ON incidents(detection_date DESC);

-- =========================================================================
-- 6. THREAT INDICATORS
-- =========================================================================
CREATE TABLE IF NOT EXISTS indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    indicator_type VARCHAR(50) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'email', 'file_hash', 'device_hash', 'mule_account_hash')),
    value TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'suspicious', 'malicious', 'benign')),
    confidence VARCHAR(50) DEFAULT 'high',
    tlp VARCHAR(20) DEFAULT 'AMBER' CHECK (tlp IN ('WHITE', 'GREEN', 'AMBER', 'RED')),
    is_community_shared BOOLEAN DEFAULT FALSE,
    description TEXT,
    source VARCHAR(255),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, indicator_type, value)
);

CREATE INDEX IF NOT EXISTS idx_indicators_org_type_val ON indicators(organization_id, indicator_type, value);

-- =========================================================================
-- 6b. UNIFIED ENTITY GRAPH & LINKAGE MODEL
-- =========================================================================
CREATE TABLE IF NOT EXISTS entities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN ('account', 'device', 'ip', 'session', 'beneficiary', 'phone_hash', 'national_id_hash')),
    entity_value TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    event_count BIGINT DEFAULT 1,
    risk_score INTEGER DEFAULT 0,
    risk_level VARCHAR(50) DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_entities_org_lookup ON entities(organization_id, entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_entities_org_risk ON entities(organization_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_entities_last_seen ON entities(organization_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS entity_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_type VARCHAR(50) NOT NULL,
    source_value TEXT NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_value TEXT NOT NULL,
    link_type VARCHAR(50) NOT NULL,
    first_linked_at TIMESTAMPTZ DEFAULT NOW(),
    last_linked_at TIMESTAMPTZ DEFAULT NOW(),
    link_count BIGINT DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, source_type, source_value, target_type, target_value, link_type)
);

CREATE INDEX IF NOT EXISTS idx_entity_links_source ON entity_links(organization_id, source_type, source_value);
CREATE INDEX IF NOT EXISTS idx_entity_links_target ON entity_links(organization_id, target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_entity_links_type ON entity_links(organization_id, link_type);

-- =========================================================================
-- 6c. DATA QUALITY & HEALTH MONITOR
-- =========================================================================
CREATE TABLE IF NOT EXISTS data_quality_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_id VARCHAR(100) NOT NULL,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL DEFAULT 'webhook',
    silence_threshold_seconds INTEGER DEFAULT 900,
    last_event_at TIMESTAMPTZ,
    total_events BIGINT DEFAULT 0,
    total_violations BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, source_id)
);

CREATE INDEX IF NOT EXISTS idx_dq_sources_org ON data_quality_sources(organization_id, source_id);
CREATE INDEX IF NOT EXISTS idx_dq_sources_last_event ON data_quality_sources(organization_id, last_event_at);

CREATE TABLE IF NOT EXISTS schema_violations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_id VARCHAR(100),
    source_name VARCHAR(255),
    violation_type VARCHAR(100) NOT NULL,
    error_message TEXT NOT NULL,
    raw_snippet JSONB DEFAULT '{}',
    occurred_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_schema_violations_org_time ON schema_violations(organization_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_schema_violations_org_type ON schema_violations(organization_id, violation_type);


-- =========================================================================
-- 7. TRANSACTIONS
-- =========================================================================
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    raw_event_id VARCHAR(100),
    account_number VARCHAR(100) NOT NULL,
    amount DECIMAL(18, 2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'ETB',
    transaction_type VARCHAR(50) NOT NULL CHECK (transaction_type IN (
        'transfer', 'withdrawal', 'deposit', 'payment', 'other'
    )),
    device_id VARCHAR(255),
    ip_address VARCHAR(45),
    location VARCHAR(255),
    transaction_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed', 'flagged', 'held')),
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicion_reasons TEXT[],
    related_incident_id UUID REFERENCES incidents(id),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transactions_org_acc ON transactions(organization_id, account_number);
CREATE INDEX IF NOT EXISTS idx_transactions_org_time ON transactions(organization_id, transaction_time DESC);

-- =========================================================================
-- 8. ALERTS
-- =========================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_system_id UUID REFERENCES target_systems(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    alert_type VARCHAR(100) NOT NULL CHECK (alert_type IN (
        'critical_incident', 'malicious_indicator', 'suspicious_transaction',
        'account_takeover', 'high_risk', 'correlation', 'api_abuse', 'other'
    )),
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    risk_score INT DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    evidence JSONB DEFAULT '{}',
    related_incident_id UUID REFERENCES incidents(id),
    related_transaction_id UUID REFERENCES transactions(id),
    related_indicator_id UUID REFERENCES indicators(id),
    assigned_to UUID REFERENCES users(id),
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_org_status ON alerts(organization_id, status);

-- =========================================================================
-- 9. DETECTION RULES & FINDINGS
-- =========================================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(50) NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    layer VARCHAR(10) NOT NULL CHECK (layer IN ('L1', 'L2', 'L3', 'L4')),
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    weight INT DEFAULT 20,
    lifecycle_state VARCHAR(20) DEFAULT 'live' CHECK (lifecycle_state IN ('draft', 'backtest', 'shadow', 'live')),
    thresholds JSONB DEFAULT '{}',
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (organization_id, id)
);

CREATE TABLE IF NOT EXISTS tenant_rule_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    threshold_overrides JSONB DEFAULT '{}',
    weight_override INTEGER,
    severity_override VARCHAR(20) CHECK (severity_override IS NULL OR severity_override IN ('low', 'medium', 'high', 'critical')),
    lifecycle_state_override VARCHAR(20) CHECK (lifecycle_state_override IS NULL OR lifecycle_state_override IN ('draft', 'backtest', 'shadow', 'live')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_rule_overrides_lookup ON tenant_rule_overrides(organization_id, rule_id);

-- =========================================================================
-- 9b. RULE LIFECYCLE, BACKTESTING & ANALYST FEEDBACK (Phase 3.2)
-- =========================================================================
CREATE TABLE IF NOT EXISTS rule_backtest_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
    rule_version VARCHAR(20) DEFAULT '1.0.0',
    status VARCHAR(20) DEFAULT 'completed' CHECK (status IN ('running', 'completed', 'failed')),
    time_range_days INTEGER DEFAULT 7,
    time_range_start TIMESTAMPTZ NOT NULL,
    time_range_end TIMESTAMPTZ NOT NULL,
    parameters JSONB DEFAULT '{}',
    events_evaluated INTEGER DEFAULT 0,
    matches_count INTEGER DEFAULT 0,
    results_summary JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rule_backtest_runs_org ON rule_backtest_runs(organization_id, rule_id, created_at DESC);

CREATE TABLE IF NOT EXISTS rule_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
    detection_id UUID REFERENCES detections(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    verdict VARCHAR(50) NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'suspicious_unconfirmed', 'benign_test')),
    analyst_notes TEXT,
    suggested_suppression JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_feedback_org ON rule_feedback(organization_id, rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rule_feedback_verdict ON rule_feedback(organization_id, verdict);

CREATE TABLE IF NOT EXISTS rule_lifecycle_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
    from_state VARCHAR(20) NOT NULL,
    to_state VARCHAR(20) NOT NULL,
    reason TEXT,
    backtest_run_id UUID REFERENCES rule_backtest_runs(id) ON DELETE SET NULL,
    changed_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_history_org ON rule_lifecycle_history(organization_id, rule_id, created_at DESC);

-- =========================================================================
-- 9c. ENTITY BEHAVIORAL BASELINES (Phase 3.4)
-- =========================================================================
CREATE TABLE IF NOT EXISTS entity_behavioral_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(100) NOT NULL,
    lookback_days INTEGER DEFAULT 90,
    sample_count INTEGER DEFAULT 0,
    amount_stats JSONB DEFAULT '{}',
    temporal_profile JSONB DEFAULT '{}',
    known_devices JSONB DEFAULT '[]',
    known_locations JSONB DEFAULT '[]',
    known_channels JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'sufficient' CHECK (status IN ('sufficient', 'insufficient_data', 'stale')),
    last_calculated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_entity_baselines_lookup ON entity_behavioral_baselines(organization_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_baselines_status ON entity_behavioral_baselines(organization_id, status);

-- =========================================================================
-- 9d. ENTITY CRITICALITY (Phase 3.5 — Risk Model v2)
-- =========================================================================
CREATE TABLE IF NOT EXISTS entity_criticality (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(100) NOT NULL,
    criticality_tier VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (criticality_tier IN ('critical', 'high', 'medium', 'low')),
    criticality_score_boost INTEGER DEFAULT 0,
    owner_unit VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_entity_criticality_lookup ON entity_criticality(organization_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_criticality_tier ON entity_criticality(organization_id, criticality_tier);


CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_detections_org_time ON detections(organization_id, detected_at DESC);

-- =========================================================================
-- 10. RESPONSE ACTIONS (Dispatched Mitigations)
-- =========================================================================
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_system_id UUID REFERENCES target_systems(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL CHECK (action_type IN ('freeze_transaction', 'revoke_session', 'block_ip', 'require_step_up', 'disable_beneficiary', 'lock_account', 'revert')),
    target_entity_type VARCHAR(50),
    target_entity_id VARCHAR(100),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'failed', 'reverted')),
    is_reverted BOOLEAN DEFAULT FALSE,
    reverted_at TIMESTAMPTZ,
    alert_id UUID REFERENCES alerts(id),
    incident_id UUID REFERENCES incidents(id),
    reason TEXT NOT NULL,
    requested_by UUID REFERENCES users(id),
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    target_response JSONB,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_actions_org_status ON response_actions(organization_id, status);

-- =========================================================================
-- 11. AUDIT LOGS (Hash-Chained Audit Trail)
-- =========================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    prev_hash VARCHAR(64),
    record_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time ON audit_logs(organization_id, created_at DESC);

-- =========================================================================
-- 12. API NONCES (Replay Prevention)
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
-- 13. SEED DEFAULT TENANT, ADMIN & RULES
-- =========================================================================
INSERT INTO organizations (id, slug, name, sector)
VALUES ('00000000-0000-0000-0000-000000000001', 'default-bank', 'Commercial Bank of Ethiopia (Primary)', 'Finance - Commercial Bank')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, organization_id, email, password_hash, full_name, role)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'admin@ethiocybershield.et',
    '$2b$12$sINKExPKues.JGwu6BQxoOrDFPypnYiSm5GiJZZF/9JcHoAW1dWSa',
    'ECS Lead SOC Administrator',
    'admin'
) ON CONFLICT DO NOTHING;

INSERT INTO target_systems (id, organization_id, name, base_url, key_id, secret_key, sync_mode, is_active, health_status)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000001',
    'ShieldBank Synthetic Testbed',
    'http://127.0.0.1:8081',
    'ecs_live_prod_key_01',
    'super-secret-key-32b',
    'bidirectional',
    TRUE,
    'healthy'
) ON CONFLICT (key_id) DO NOTHING;
