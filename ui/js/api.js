/**
 * Ethio-Cyber Shield API Client
 * Vanilla JS - no frameworks
 */

const API = {
    getToken() {
        return localStorage.getItem(CONFIG.TOKEN_KEY);
    },

    setAuth(token, user) {
        localStorage.setItem(CONFIG.TOKEN_KEY, token);
        localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
    },

    clearAuth() {
        localStorage.removeItem(CONFIG.TOKEN_KEY);
        localStorage.removeItem(CONFIG.USER_KEY);
    },

    getUser() {
        try {
            return JSON.parse(localStorage.getItem(CONFIG.USER_KEY) || 'null');
        } catch {
            return null;
        }
    },

    isAuthenticated() {
        return !!this.getToken();
    },

    getTenant() {
        return localStorage.getItem('ecs_tenant_id');
    },

    setTenant(tenantId) {
        if (tenantId) {
            localStorage.setItem('ecs_tenant_id', tenantId);
        } else {
            localStorage.removeItem('ecs_tenant_id');
        }
    },

    async request(method, path, body = null) {
        const headers = {
            'Content-Type': 'application/json'
        };
        const token = this.getToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        const tenant = this.getTenant();
        if (tenant) {
            headers['X-ECS-Tenant'] = tenant;
        }

        const opts = { method, headers };
        if (body && method !== 'GET') {
            opts.body = JSON.stringify(body);
        }

        const res = await fetch(`${CONFIG.API_BASE_URL}${path}`, opts);
        
        if (res.status === 401) {
            this.clearAuth();
            if (!window.location.pathname.includes('login')) {
                window.location.href = 'login.html?session_expired=concurrent';
            }
            throw new Error('Unauthorized');
        }

        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `Request failed (${res.status})`);
        }
        return data;
    },

    // Auth
    login(email, password) {
        return this.request('POST', '/auth/login', { email, password });
    },
    logout() {
        return this.request('POST', '/auth/logout');
    },
    me() {
        return this.request('GET', '/auth/me');
    },

    // Incidents
    getIncidents(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/incidents${q ? '?' + q : ''}`);
    },
    getIncident(id) {
        return this.request('GET', `/incidents/${id}`);
    },
    createIncident(data) {
        return this.request('POST', '/incidents', data);
    },
    updateIncident(id, data) {
        return this.request('PUT', `/incidents/${id}`, data);
    },
    analyzeIncident(id) {
        return this.request('POST', `/incidents/${id}/analyze`);
    },
    linkIndicator(incidentId, indicatorId, notes = '') {
        return this.request('POST', `/incidents/${incidentId}/indicators`, { indicator_id: indicatorId, notes });
    },

    // Indicators
    getIndicators(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/indicators${q ? '?' + q : ''}`);
    },
    getIndicator(id) {
        return this.request('GET', `/indicators/${id}`);
    },
    createIndicator(data) {
        return this.request('POST', '/indicators', data);
    },
    updateIndicator(id, data) {
        return this.request('PUT', `/indicators/${id}`, data);
    },

    // Transactions
    getTransactions(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/transactions${q ? '?' + q : ''}`);
    },
    createTransaction(data) {
        return this.request('POST', '/transactions', data);
    },
    analyzeTransaction(id) {
        return this.request('POST', `/transactions/${id}/analyze`);
    },

    // Alerts
    getAlerts(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/alerts${q ? '?' + q : ''}`);
    },
    getAlert(id) {
        return this.request('GET', `/alerts/${id}`);
    },
    getAlertDossier(id) {
        return this.request('GET', `/alerts/${id}/dossier`);
    },
    acknowledgeAlert(id) {
        return this.request('POST', `/alerts/${id}/acknowledge`);
    },
    resolveAlert(id, status = 'resolved') {
        return this.request('POST', `/alerts/${id}/resolve`, { status });
    },

    // Dashboard
    getDashboardStats() {
        return this.request('GET', '/dashboard/stats');
    },

    // Audit
    getAuditLogs(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/audit${q ? '?' + q : ''}`);
    },

    // Users (admin)
    getUsers() {
        return this.request('GET', '/auth/users');
    },



    // Watchlists
    getWatchlists(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/watchlists${q ? '?' + q : ''}`);
    },
    createWatchlist(data) {
        return this.request('POST', '/watchlists', data);
    },
    updateWatchlist(id, data) {
        return this.request('PUT', `/watchlists/${id}`, data);
    },
    deleteWatchlist(id) {
        return this.request('DELETE', `/watchlists/${id}`);
    },
    clearWatchlists(mode = 'deactivate') {
        return this.request('POST', '/watchlists/clear', { mode });
    },

    // Settings
    getFraudRules() {
        return this.request('GET', '/settings/fraud-rules');
    },
    updateFraudRules(data) {
        return this.request('PUT', '/settings/fraud-rules', data);
    },

    // Reports
    getReportSummary(days = 7) {
        return this.request('GET', `/reports/summary?days=${days}`);
    },
    exportCsvUrl(type = 'transactions', days = 30) {
        const token = this.getToken();
        return `${CONFIG.API_BASE_URL}/reports/export.csv?type=${encodeURIComponent(type)}&days=${days}&token=${encodeURIComponent(token || '')}`;
    },

    // Alerts workflow
    assignAlert(id, assigned_to) {
        return this.request('POST', `/alerts/${id}/assign`, { assigned_to });
    },
    getAlertNotes(id) {
        return this.request('GET', `/alerts/${id}/notes`);
    },
    addAlertNote(id, note) {
        return this.request('POST', `/alerts/${id}/notes`, { note });
    },
    deleteAlert(id) {
        return this.request('DELETE', `/alerts/${id}`);
    },
    acknowledgeAlert(id) {
        return this.request('POST', `/alerts/${id}/acknowledge`);
    },
    resolveAlert(id, status = 'resolved') {
        return this.request('POST', `/alerts/${id}/resolve`, { status });
    },

    // Transactions CRUD
    updateTransaction(id, data) {
        return this.request('PUT', `/transactions/${id}`, data);
    },
    deleteTransaction(id) {
        return this.request('DELETE', `/transactions/${id}`);
    },

    // Users
    updateUser(id, data) {
        return this.request('PUT', `/auth/users/${id}`, data);
    },
    deleteUser(id) {
        return this.request('DELETE', `/auth/users/${id}`);
    },
    createUser(data) {
        return this.request('POST', '/auth/users', data);
    },
    // Live threat detection
    getLiveSummary(minutes = 60) {
        return this.request('GET', `/live/summary?minutes=${minutes}`);
    },
    getLiveTimeline(minutes = 60, bucket = 5) {
        return this.request('GET', `/live/timeline?minutes=${minutes}&bucket=${bucket}`);
    },
    getLiveEvents(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/live/recent-events${q ? '?' + q : ''}`);
    },
    // Password reset (Supabase-backed via Python API)
    forgotPassword(email) {
        return this.request('POST', '/auth/forgot-password', { email });
    },
    resetPassword(token, password) {
        return this.request('POST', '/auth/reset-password', { token, password });
    },

    // Target Systems Management
    getTargets() {
        return this.request('GET', '/targets');
    },
    getTargetSystems() {
        return this.getTargets();
    },
    getTarget(id) {
        return this.request('GET', `/targets/${id}`);
    },
    registerTarget(data) {
        return this.request('POST', '/targets', data);
    },
    registerTargetSystem(data) {
        return this.registerTarget(data);
    },
    deleteTarget(id) {
        return this.request('DELETE', `/targets/${id}`);
    },
    deleteTargetSystem(id) {
        return this.deleteTarget(id);
    },
    testTargetHealth(id) {
        return this.request('POST', `/targets/${id}/test-health`);
    },
    pollTargetNow(id = 'default-target-shieldbank') {
        return this.request('POST', `/targets/${id}/poll-now`);
    },
    pollTargetTelemetry(id = 'default-target-shieldbank') {
        return this.pollTargetNow(id);
    },
    getTargetStats(id) {
        return this.request('GET', `/targets/${id}/stats`);
    },

    // Lab Scenario Orchestrator
    getScenarios() {
        return this.request('GET', '/live/scenarios');
    },
    triggerScenario(data) {
        return this.request('POST', '/live/trigger-scenario', data);
    },
    getStreamEvents(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/live/stream-events${q ? '?' + q : ''}`);
    },

    // Attack Graph & Incident Explainability
    getIncidentAttackGraph(incidentId) {
        return this.request('GET', `/incidents/${incidentId}/attack-graph`);
    },
    promoteAlertToIncident(alertId) {
        return this.request('POST', `/incidents/promote-alert/${alertId}`);
    },

    // Response Actions & Mitigations
    getResponseActions(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('GET', `/targets/actions${q ? '?' + q : ''}`);
    },
    executeTargetControl(targetId, data) {
        return this.request('POST', `/targets/${targetId}/execute-control`, data);
    },
    blockAttackerIp(ip, reason = 'Attacker containment dispatched by ECS') {
        return this.executeTargetControl('default-target-shieldbank', {
            action_type: 'block-ip',
            entity_id: ip,
            reason: reason
        });
    },
    revokeAttackerSession(accountOrSession, reason = 'Compromised session revoked by ECS') {
        return this.executeTargetControl('default-target-shieldbank', {
            action_type: 'revoke-session',
            entity_id: accountOrSession,
            reason: reason
        });
    },
    freezeSuspiciousTransaction(accountOrTx, reason = 'Transaction held for review') {
        return this.executeTargetControl('default-target-shieldbank', {
            action_type: 'freeze-transaction',
            entity_id: accountOrTx,
            reason: reason
        });
    },
    revertAction(actionId, reason = 'Analyst rollback') {
        return this.request('POST', `/targets/actions/${actionId}/revert`, { reason });
    },
    getAutoContainment() {
        return this.request('GET', '/targets/settings/auto-containment');
    },
    setAutoContainment(enabled) {
        return this.request('POST', '/targets/settings/auto-containment', { enabled });
    },

    // Identity, MFA & Scoped API Tokens
    verifyMfa(mfaToken, code) {
        return this.request('POST', '/auth/mfa/verify', { mfa_token: mfaToken, code });
    },
    setupMfa() {
        return this.request('POST', '/auth/mfa/setup');
    },
    enableMfa(secret, code) {
        return this.request('POST', '/auth/mfa/enable', { secret, code });
    },
    listApiTokens() {
        return this.request('GET', '/auth/api-tokens');
    },
    createApiToken(name, scopes = ['ingest:events'], expiresDays = 90) {
        return this.request('POST', '/auth/api-tokens', { name, scopes, expires_days: expiresDays });
    },
    revokeApiToken(tokenId) {
        return this.request('DELETE', `/auth/api-tokens/${tokenId}`);
    },

    // Tamper-Evident Audit & Verification
    verifyAuditChain() {
        return this.request('POST', '/audit/verify');
    },
    exportAuditAnchor() {
        return this.request('POST', '/audit/anchor');
    },

    // System Health
    getPlatformHealth() {
        return this.request('GET', '/health');
    }
};

