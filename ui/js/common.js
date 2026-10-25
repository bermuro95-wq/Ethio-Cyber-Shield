/**
 * Common UI helpers for Ethio-Cyber Shield
 */

function requireAuth(roles = null) {
    if (!API.isAuthenticated()) {
        window.location.href = 'login.html';
        return false;
    }
    if (roles) {
        const user = API.getUser();
        if (!user) {
            window.location.href = 'login.html';
            return false;
        }
        const userRole = (user.role || '').toLowerCase();
        const isSuperadmin = user.is_superadmin || userRole === 'superadmin' || user.email === 'admin@ethiocybershield.et' || user.email === 'admin';
        const normalizedRoles = roles.map(r => String(r).toLowerCase());
        if (!isSuperadmin && !normalizedRoles.includes(userRole)) {
            alert('Access denied. Insufficient permissions.');
            window.location.href = 'dashboard.html';
            return false;
        }
    }
    return true;
}

function renderNavbar(activePage = '') {
    const user = API.getUser();
    const name = user ? (user.full_name || user.email || 'SOC Operator') : 'SOC Operator';
    const role = (user && user.role) ? user.role.toLowerCase() : 'admin';
    const orgName = (user && (user.organization_name || user.organization_id)) ? (user.organization_name || user.organization_id) : 'National SOC';
    const isSuperadmin = user && (user.is_superadmin || user.role === 'superadmin' || user.email === 'admin@ethiocybershield.et' || user.email === 'admin' || user.organization_id === '00000000-0000-0000-0000-000000000001');

    const isOverview = activePage === 'dashboard' || activePage === 'live';
    const isAlerts = activePage === 'alerts';
    const isAnalysis = activePage === 'analysis';
    const isIncidents = activePage === 'incidents' || activePage === 'incident-detail';
    const isIntel = activePage === 'intelligence' || activePage === 'indicators' || activePage === 'fraud' || activePage === 'watchlists';
    const isAudit = activePage === 'audit' || activePage === 'reports';
    const isSettings = activePage === 'settings';
    const isTenants = activePage === 'tenants';
    const isUsers = activePage === 'users';

    const soundBtnHtml = `
        <button class="ecs-header-btn ${isSoundEnabled() ? 'ecs-header-btn-sound-on' : 'ecs-header-btn-sound-off'}" id="btnSoundToggle" onclick="toggleSound()" title="${isSoundEnabled() ? 'Audio threat notifications active. Click to mute.' : 'Audio threat notifications muted. Click to enable sound.'}">
            <i class="bi ${isSoundEnabled() ? 'bi-volume-up-fill' : 'bi-volume-mute-fill'} me-1"></i><span>Sound: ${isSoundEnabled() ? 'ON' : 'OFF'}</span>
        </button>
    `;

    // SaaS Tenants and Users nav links
    let saasLinksHtml = '';
    if (isSuperadmin) {
        saasLinksHtml += `
            <a class="ecs-nav-link ${isTenants ? 'active' : ''}" href="tenants.html" title="SaaS Tenant Organizations & SDK Onboarding">
                <i class="bi bi-buildings"></i>
                <span>Tenants (SaaS)</span>
            </a>
            <a class="ecs-nav-link ${isUsers ? 'active' : ''}" href="users.html" title="Cross-Tenant User Management & Access Control">
                <i class="bi bi-people"></i>
                <span>User Control</span>
            </a>
        `;
    } else if (role === 'admin') {
        saasLinksHtml += `
            <a class="ecs-nav-link ${isUsers ? 'active' : ''}" href="users.html" title="Manage Organization Users">
                <i class="bi bi-people"></i>
                <span>Users</span>
            </a>
        `;
    }

    // Tenant Switcher dropdown or Institutional Tag
    let tenantScopeHtml = '';
    if (isSuperadmin) {
        const curTenant = API.getSelectedTenant();
        tenantScopeHtml = `
            <div class="ecs-tenant-switcher-wrapper d-flex align-items-center gap-1" title="Platform Tenant Viewport">
                <i class="bi bi-building text-warning small"></i>
                <select id="globalTenantSwitcher" class="form-select form-select-sm bg-dark text-light border-secondary font-mono py-0 px-2" style="font-size: 0.75rem; height: 28px; max-width: 170px;" onchange="onGlobalTenantSwitch(this.value)">
                    <option value="all" ${curTenant === 'all' ? 'selected' : ''}>🏢 All Tenants</option>
                </select>
            </div>
        `;
    } else {
        tenantScopeHtml = `
            <div class="ecs-org-tag" title="Authenticated Tenant Scope: ${escapeHtml(orgName)}">
                <i class="bi bi-building"></i>
                <span class="font-mono text-truncate" style="max-width: 140px;">${escapeHtml(orgName)}</span>
            </div>
        `;
    }

    // Asynchronously populate tenant options if superadmin
    if (isSuperadmin) {
        setTimeout(loadTenantSwitcherOptions, 50);
    }

    return `
    <header class="ecs-navbar-header sticky-top">
        <div class="ecs-nav-container">
            <!-- Left: Institutional Branding -->
            <div class="ecs-brand-wrapper">
                <a class="ecs-brand-link" href="dashboard.html" title="Ethio-Cyber Shield SOC Command">
                    <img src="assets/logo-shield.jpg" alt="ECS Shield" class="ecs-brand-icon" width="28" height="28">
                    <div class="ecs-brand-titles">
                        <span class="ecs-brand-main">ETHIO-CYBER SHIELD</span>
                        <span class="ecs-brand-sub">${isSuperadmin ? 'NATIONAL SAAS SOC PLATFORM' : escapeHtml(orgName.toUpperCase())}</span>
                    </div>
                </a>
            </div>

            <!-- Center: Core SOC Navigation Links (Always Visible, 1-Click Direct Access) -->
            <nav class="ecs-nav-links" aria-label="Main Security Operations Navigation">
                <a class="ecs-nav-link ${isOverview ? 'active' : ''}" href="dashboard.html">
                    <i class="bi bi-grid-1x2"></i>
                    <span>Overview</span>
                </a>
                <a class="ecs-nav-link ${isAlerts ? 'active' : ''}" href="alerts.html">
                    <i class="bi bi-bell"></i>
                    <span>Alerts</span>
                </a>
                <a class="ecs-nav-link ${isAnalysis ? 'active' : ''}" href="analysis.html" title="Attack Pivot & Multi-Dimensional Entity Correlation Analysis">
                    <i class="bi bi-diagram-3"></i>
                    <span>Analysis</span>
                </a>
                <a class="ecs-nav-link ${isIncidents ? 'active' : ''}" href="incidents.html">
                    <i class="bi bi-shield-exclamation"></i>
                    <span>Incidents</span>
                </a>
                <a class="ecs-nav-link ${isIntel ? 'active' : ''}" href="intelligence.html">
                    <i class="bi bi-cpu"></i>
                    <span>Threat Intel</span>
                </a>
                <a class="ecs-nav-link ${isAudit ? 'active' : ''}" href="audit.html">
                    <i class="bi bi-journal-check"></i>
                    <span>Audit & Compliance</span>
                </a>
                <a class="ecs-nav-link ${isSettings ? 'active' : ''}" href="settings.html">
                    <i class="bi bi-sliders"></i>
                    <span>Settings & Rules</span>
                </a>
                ${saasLinksHtml}
            </nav>

            <!-- Right: Operational Controls & Session Metadata -->
            <div class="ecs-nav-controls">
                <!-- Real-Time Stream Status -->
                <div class="ecs-stream-pill" title="Deterministic Telemetry Stream Connected">
                    <span class="ecs-stream-dot"></span>
                    <span class="ecs-stream-label">STREAM LIVE</span>
                </div>

                <!-- Audible Alarm Toggle -->
                ${soundBtnHtml}

                <!-- Tenant / Sector Indicator or Switcher -->
                ${tenantScopeHtml}

                <!-- Operator Identity Badge -->
                <div class="ecs-user-badge" title="Active Security Operator">
                    <i class="bi bi-person-circle"></i>
                    <span class="ecs-user-name">${escapeHtml(name)}</span>
                    <span class="ecs-role-pill">${escapeHtml(isSuperadmin ? 'SUPERADMIN' : role.toUpperCase())}</span>
                </div>

                <!-- Sign Out -->
                <button class="ecs-logout-btn" onclick="doLogout()" title="Sign out session">
                    <i class="bi bi-box-arrow-right"></i>
                    <span>Sign Out</span>
                </button>
            </div>
        </div>
    </header>`;
}

function onGlobalTenantSwitch(tenantId) {
    API.setSelectedTenant(tenantId);
    showToast(`Active tenant context updated: ${tenantId === 'all' ? 'All Tenants (Global Platform)' : 'Scoped Organization'}`);
    setTimeout(() => {
        window.location.reload();
    }, 350);
}

async function loadTenantSwitcherOptions() {
    const sel = document.getElementById('globalTenantSwitcher');
    if (!sel) return;
    try {
        const tenants = await API.getTenants();
        const cur = API.getSelectedTenant();
        let opts = `<option value="all" ${cur === 'all' ? 'selected' : ''}>🏢 All Tenants (Global)</option>`;
        if (Array.isArray(tenants)) {
            tenants.forEach(t => {
                const isSel = String(t.id) === String(cur);
                opts += `<option value="${t.id}" ${isSel ? 'selected' : ''}>🏛️ ${escapeHtml(t.name || t.slug)}</option>`;
            });
        }
        sel.innerHTML = opts;
    } catch (e) {
        console.debug('Tenant switcher load notice:', e);
    }
}

async function doLogout() {
    try { await API.logout(); } catch(e) {}
    API.clearAuth();
    window.location.href = 'login.html';
}

function severityBadge(sev) {
    const s = (sev || 'low').toLowerCase();
    const cls = s === 'critical' ? 'badge-critical' :
                s === 'high' ? 'badge-high' :
                s === 'medium' ? 'badge-medium' : 'badge-low';
    return `<span class="badge ${cls} text-uppercase font-mono">${escapeHtml(s)}</span>`;
}

function statusBadge(status) {
    const s = (status || 'unknown').toLowerCase();
    let cls = 'badge-soc-neutral';
    if (['open', 'critical', 'malicious', 'flagged'].includes(s)) {
        cls = 'badge-critical';
    } else if (['investigating', 'high', 'suspicious', 'pending'].includes(s)) {
        cls = 'badge-high';
    } else if (['contained', 'acknowledged', 'medium'].includes(s)) {
        cls = 'badge-medium';
    } else if (['resolved', 'closed', 'benign', 'completed'].includes(s)) {
        cls = 'badge-soc-neutral';
    }
    return `<span class="badge ${cls} font-mono">${escapeHtml(s.replace(/_/g, ' '))}</span>`;
}

function riskBadge(level) {
    return severityBadge(level);
}

function formatDate(iso) {
    if (!iso) return '-';
    try {
        return new Date(iso).toLocaleString('en-ET', { timeZone: 'Africa/Addis_Ababa' });
    } catch {
        return iso;
    }
}

function showToast(message, type = 'success') {
    const id = 'toast-' + Date.now();
    const bg = type === 'error' ? 'danger' : type === 'warning' ? 'warning' : 'success';
    const html = `
    <div id="${id}" class="toast align-items-center text-bg-${bg} border-0 position-fixed bottom-0 end-0 m-3" role="alert" style="z-index:9999">
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    </div>`;
    document.body.insertAdjacentHTML('beforeend', html);
    const el = document.getElementById(id);
    const t = new bootstrap.Toast(el, { delay: 3500 });
    t.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function loadingSpinner(targetId) {
    const el = document.getElementById(targetId);
    if (el) el.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-success" role="status"></div><p class="mt-2 text-muted">Loading...</p></div>';
}

function noData(msg = 'No data available.') {
    return `<div class="text-center text-muted py-5"><i class="bi bi-inbox fs-1"></i><p class="mt-2">${msg}</p></div>`;
}

// -----------------------------------------------------------------------------
// Real-Time Notification & Dynamic Sound Engine
// -----------------------------------------------------------------------------

let _ecsEventSource = null;
let _ecsReconnectTimer = null;
let _ecsLastSeenAlert = null;
const _seenAlertIds = new Set();

let _ecsSoundEnabled = localStorage.getItem('ecs_sound_enabled') !== 'false';
let _audioCtx = null;

function getAudioContext() {
    if (!_audioCtx) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
            _audioCtx = new AudioCtx();
        }
    }
    if (_audioCtx && _audioCtx.state === 'suspended') {
        _audioCtx.resume().catch(() => {});
    }
    return _audioCtx;
}

// User-gesture audio unlock so browser autoplay policy never blocks alerts
if (typeof document !== 'undefined') {
    document.addEventListener('click', () => {
        getAudioContext();
    }, { once: true });
}

function isSoundEnabled() {
    return _ecsSoundEnabled;
}

function setSoundEnabled(enabled) {
    _ecsSoundEnabled = !!enabled;
    localStorage.setItem('ecs_sound_enabled', _ecsSoundEnabled ? 'true' : 'false');
    updateSoundToggleButton();
}

function toggleSound() {
    setSoundEnabled(!_ecsSoundEnabled);
    if (_ecsSoundEnabled) {
        playAlertTone('medium', true);
        showToast('Threat Audio Alert: ENABLED', 'success');
    } else {
        showToast('Threat Audio Alert: MUTED', 'warning');
    }
}

function updateSoundToggleButton() {
    const btn = document.getElementById('btnSoundToggle');
    if (!btn) return;
    if (_ecsSoundEnabled) {
        btn.innerHTML = '<i class="bi bi-volume-up-fill me-1"></i><span>Sound: ON</span>';
        btn.className = 'ecs-header-btn ecs-header-btn-sound-on';
        btn.title = 'Audio threat notifications active. Click to mute.';
    } else {
        btn.innerHTML = '<i class="bi bi-volume-mute-fill me-1"></i><span>Sound: OFF</span>';
        btn.className = 'ecs-header-btn ecs-header-btn-sound-off';
        btn.title = 'Audio threat notifications muted. Click to enable sound.';
    }
}

let _lastSoundPlayedTime = 0;

function playAlertTone(severity = 'medium', force = false) {
    if (!_ecsSoundEnabled && !force) return;
    const nowMs = Date.now();
    if (!force && nowMs - _lastSoundPlayedTime < 1800) {
        return; // Throttle audio alarms to max once every 1.8s
    }
    _lastSoundPlayedTime = nowMs;

    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;
        const sev = (severity || 'medium').toLowerCase();

        if (sev === 'critical') {
            // High-urgency warble siren (880Hz -> 1046Hz -> 880Hz -> 1174Hz)
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.linearRampToValueAtTime(1046, now + 0.12);
            osc.frequency.linearRampToValueAtTime(880, now + 0.24);
            osc.frequency.linearRampToValueAtTime(1174, now + 0.36);
            gain.gain.setValueAtTime(0.24, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.55);
            osc.start(now);
            osc.stop(now + 0.58);
        } else if (sev === 'high') {
            // Rapid double alert beep (740Hz)
            [0, 0.16].forEach(offset => {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.type = 'square';
                osc.frequency.setValueAtTime(740, now + offset);
                gain.gain.setValueAtTime(0.18, now + offset);
                gain.gain.exponentialRampToValueAtTime(0.001, now + offset + 0.12);
                osc.start(now + offset);
                osc.stop(now + offset + 0.13);
            });
        } else if (sev === 'medium') {
            // Melodic notification chime (587Hz -> 784Hz)
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(587, now);
            osc.frequency.exponentialRampToValueAtTime(784, now + 0.18);
            gain.gain.setValueAtTime(0.18, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.32);
            osc.start(now);
            osc.stop(now + 0.35);
        } else {
            // Subtle ping (440Hz)
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(440, now);
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
            osc.start(now);
            osc.stop(now + 0.20);
        }
    } catch (e) {
        // Audio blocked
    }
}

// -----------------------------------------------------------------------------
// Real-Time Time Formatting & Dynamic Elapsed Ticker
// -----------------------------------------------------------------------------

function getRelativeTime(dateOrIso) {
    if (!dateOrIso) return '-';
    try {
        const d = dateOrIso instanceof Date ? dateOrIso : new Date(dateOrIso);
        const diffMs = Date.now() - d.getTime();
        const diffSec = Math.max(0, Math.floor(diffMs / 1000));
        if (diffSec < 5) return 'Just now';
        if (diffSec < 60) return `${diffSec}s ago`;
        const diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) return `${diffMin}m ago`;
        const diffHours = Math.floor(diffMin / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
    } catch {
        return '-';
    }
}

function formatThreatTime(isoStr) {
    if (!isoStr) return { relative: '-', full: '-', timeOnly: '-', dateOnly: '-', raw: '' };
    try {
        const d = new Date(isoStr);
        const timeOnly = d.toLocaleTimeString('en-ET', { timeZone: 'Africa/Addis_Ababa', hour12: false });
        const dateOnly = d.toLocaleDateString('en-ET', { timeZone: 'Africa/Addis_Ababa', year: 'numeric', month: 'short', day: 'numeric' });
        const full = `${dateOnly} ${timeOnly} EAT`;
        const relative = getRelativeTime(d);
        return { relative, full, timeOnly, dateOnly, raw: isoStr };
    } catch {
        return { relative: '-', full: String(isoStr), timeOnly: String(isoStr).slice(11, 19), dateOnly: '-', raw: isoStr };
    }
}

// Dynamic interval updating all threat timers on the page in real-time
// Throttled to 4s and paused when tab is hidden to prevent browser lag & CPU thrashing
if (typeof setInterval !== 'undefined') {
    setInterval(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        document.querySelectorAll('[data-threat-time]').forEach(el => {
            const iso = el.getAttribute('data-threat-time');
            if (iso) {
                const rel = getRelativeTime(iso);
                const relSpan = el.querySelector('.time-relative');
                if (relSpan) relSpan.textContent = rel;
            }
        });
    }, 4000);
}

let _lastToastTime = 0;

function showInstantAlertNotification(alertData) {
    if (!alertData || !alertData.id) return;
    if (_seenAlertIds.has(alertData.id)) return;
    _seenAlertIds.add(alertData.id);

    if (_seenAlertIds.size > 200) {
        const first = _seenAlertIds.values().next().value;
        _seenAlertIds.delete(first);
    }

    const nowMs = Date.now();
    if (nowMs - _lastToastTime < 1500) {
        return; // Throttle visual toast popups to prevent DOM spam
    }
    _lastToastTime = nowMs;

    let container = document.getElementById('ecs-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'ecs-toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '10999';
        document.body.appendChild(container);
    }

    // Limit maximum visible toasts to 3 so DOM doesn't get flooded
    while (container.children.length >= 3) {
        container.removeChild(container.firstChild);
    }

    const sev = (alertData.severity || 'medium').toLowerCase();
    const borderMap = { critical: 'danger', high: 'warning', medium: 'info', low: 'secondary' };
    const badgeMap = { critical: 'danger', high: 'warning', medium: 'info', low: 'secondary' };
    const borderClass = borderMap[sev] || 'info';
    const badgeClass = badgeMap[sev] || 'info';

    const tInfo = formatThreatTime(alertData.created_at || alertData.occurred_at || new Date().toISOString());
    const toastId = 'alert-toast-' + alertData.id.replace(/[^a-zA-Z0-9_-]/g, '');
    const html = `
    <div id="${toastId}" class="toast border border-${borderClass} shadow-lg mb-2 text-light" role="alert" aria-live="assertive" aria-atomic="true" style="background: rgba(18, 22, 28, 0.96); backdrop-filter: blur(8px); min-width: 320px; max-width: 420px;">
        <div class="toast-header bg-dark text-light border-bottom border-secondary d-flex justify-content-between align-items-center py-2">
            <div class="d-flex align-items-center gap-2">
                <span class="badge bg-${badgeClass} text-uppercase fw-bold">${escapeHtml(sev)}</span>
                <span class="fw-semibold text-truncate" style="max-width: 200px;" title="${escapeHtml(alertData.title || 'Threat Detected')}">
                    <i class="bi bi-shield-exclamation text-${borderClass} me-1"></i>${escapeHtml(alertData.title || 'Security Alert')}
                </span>
            </div>
            <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
        <div class="toast-body py-2">
            <div class="d-flex justify-content-between align-items-center mb-1 text-muted small" style="font-size:0.75rem;">
                <span><i class="bi bi-clock-history me-1 text-warning"></i>Time Attacked:</span>
                <span class="font-mono text-warning">${escapeHtml(tInfo.timeOnly)} EAT (${escapeHtml(tInfo.relative)})</span>
            </div>
            <div class="small text-light mb-2">${escapeHtml(alertData.description || 'Deterministic rule matched suspicious event telemetry.')}</div>
            <div class="d-flex justify-content-between align-items-center pt-2 border-top border-secondary small">
                <div>
                    ${alertData.risk_score ? `<span class="badge bg-dark border border-secondary text-warning me-1">Risk ${alertData.risk_score}</span>` : ''}
                    <span class="badge bg-secondary">${escapeHtml(alertData.alert_type || 'DETECTION')}</span>
                </div>
                <a href="alerts.html" class="btn btn-sm btn-outline-danger py-0 px-2 small">Triage &rarr;</a>
            </div>
        </div>
    </div>`;

    container.insertAdjacentHTML('beforeend', html);
    const toastEl = document.getElementById(toastId);
    if (toastEl && typeof bootstrap !== 'undefined' && bootstrap.Toast) {
        const bsToast = new bootstrap.Toast(toastEl, { delay: 9000 });
        bsToast.show();
        toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
    }

    playAlertTone(sev);
}

function shouldEnableRealTimeStream() {
    if (typeof window === 'undefined') return false;
    const path = (window.location.pathname || '').toLowerCase();
    // Only live monitoring pages need dedicated persistent SSE connections
    return path.includes('dashboard') || path.includes('alerts') || path.endsWith('/') || path.endsWith('/ui/');
}

function initRealTimeStream() {
    if (typeof API === 'undefined' || !API.isAuthenticated()) return;
    if (!shouldEnableRealTimeStream()) return;
    if (typeof document !== 'undefined' && document.hidden) return;

    if (_ecsEventSource && _ecsEventSource.readyState !== EventSource.CLOSED) {
        return;
    }
    if (_ecsReconnectTimer) {
        clearTimeout(_ecsReconnectTimer);
        _ecsReconnectTimer = null;
    }

    const token = API.getToken();
    if (!token) return;

    if (!_ecsLastSeenAlert) {
        _ecsLastSeenAlert = new Date(Date.now() - 15000).toISOString();
    }

    const baseUrl = (typeof CONFIG !== 'undefined' && CONFIG.API_BASE_URL) ? CONFIG.API_BASE_URL : '/api';
    const sseUrl = `${baseUrl}/live/stream?token=${encodeURIComponent(token)}&since=${encodeURIComponent(_ecsLastSeenAlert)}`;

    try {
        _ecsEventSource = new EventSource(sseUrl);

        _ecsEventSource.addEventListener('alert', (event) => {
            try {
                const alertData = JSON.parse(event.data);
                if (alertData.created_at) {
                    _ecsLastSeenAlert = alertData.created_at;
                }
                showInstantAlertNotification(alertData);

                if (typeof window._onRealtimeAlert === 'function') {
                    window._onRealtimeAlert(alertData);
                }
            } catch (err) {
                console.error('[ECS Realtime] Parse error:', err);
            }
        });

        _ecsEventSource.addEventListener('ping', () => {
            // Heartbeat ok
        });

        _ecsEventSource.onerror = () => {
            if (_ecsEventSource) {
                try { _ecsEventSource.close(); } catch (e) {}
                _ecsEventSource = null;
            }
            if (!_ecsReconnectTimer && !document.hidden && shouldEnableRealTimeStream()) {
                _ecsReconnectTimer = setTimeout(() => {
                    _ecsReconnectTimer = null;
                    initRealTimeStream();
                }, 5000);
            }
        };
    } catch (err) {
        console.warn('[ECS Realtime] Connection error, retrying in 8s:', err);
        if (!_ecsReconnectTimer && !document.hidden && shouldEnableRealTimeStream()) {
            _ecsReconnectTimer = setTimeout(initRealTimeStream, 8000);
        }
    }
}

function closeRealTimeStream() {
    if (_ecsEventSource) {
        try { _ecsEventSource.close(); } catch(e) {}
        _ecsEventSource = null;
    }
    if (_ecsReconnectTimer) {
        clearTimeout(_ecsReconnectTimer);
        _ecsReconnectTimer = null;
    }
}

// Pause SSE when tab is hidden or backgrounded, resume when active
if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            closeRealTimeStream();
        } else {
            if (shouldEnableRealTimeStream() && typeof API !== 'undefined' && API.isAuthenticated()) {
                initRealTimeStream();
            }
        }
    });
}

window.addEventListener('beforeunload', closeRealTimeStream);
window.addEventListener('pagehide', closeRealTimeStream);

// Auto-initialize real-time stream and sound button across relevant pages
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        updateSoundToggleButton();
        if (shouldEnableRealTimeStream() && typeof API !== 'undefined' && API.isAuthenticated()) {
            initRealTimeStream();
        }
    });
} else {
    updateSoundToggleButton();
    if (shouldEnableRealTimeStream() && typeof API !== 'undefined' && API.isAuthenticated()) {
        initRealTimeStream();
    }
}
