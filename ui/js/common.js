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
        if (!user || !roles.includes(user.role)) {
            alert('Access denied. Insufficient permissions.');
            window.location.href = 'dashboard.html';
            return false;
        }
    }
    return true;
}

function renderNavbar(activePage = '') {
    const user = API.getUser();
    const name = user ? user.full_name : 'Admin';
    const role = (user && user.role) ? user.role.toLowerCase() : 'viewer';
    const orgId = user && user.organization_id ? user.organization_id.slice(0, 8) + '...' : 'Default Org';

    // Role-aware navigation permissions
    const canViewSoc = ['admin', 'analyst', 'responder', 'viewer'].includes(role);
    const canViewIncidents = ['admin', 'analyst', 'responder', 'auditor'].includes(role);
    const canViewAudit = ['admin', 'analyst', 'auditor'].includes(role);
    const canViewAdmin = ['admin'].includes(role);

    let linksHtml = '';
    if (canViewSoc) {
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='dashboard' || activePage==='live' ?'active':''}" href="dashboard.html"><i class="bi bi-grid-1x2 me-1"></i>Overview</a></li>`;
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='alerts'?'active':''}" href="alerts.html"><i class="bi bi-bell me-1"></i>Alerts</a></li>`;
    }
    if (canViewIncidents) {
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='incidents' || activePage==='incident-detail' ?'active':''}" href="incidents.html"><i class="bi bi-shield-exclamation me-1"></i>Incidents</a></li>`;
    }
    if (['admin', 'analyst', 'viewer'].includes(role)) {
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='intelligence' || activePage==='indicators' || activePage==='fraud' || activePage==='watchlists' ?'active':''}" href="intelligence.html"><i class="bi bi-cpu me-1"></i>Intelligence</a></li>`;
    }
    if (canViewAudit) {
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='audit' || activePage==='reports' ?'active':''}" href="audit.html"><i class="bi bi-journal-check me-1"></i>Audit & Reports</a></li>`;
    }
    if (canViewAdmin) {
        linksHtml += `<li class="nav-item"><a class="nav-link ${activePage==='settings' || activePage==='users' ?'active':''}" href="settings.html"><i class="bi bi-sliders me-1"></i>Settings</a></li>`;
    }

    return `
    <nav class="navbar navbar-expand-lg ecs-navbar sticky-top">
        <div class="container-fluid px-3">
            <a class="navbar-brand d-flex align-items-center gap-2" href="dashboard.html">
                <img src="assets/logo-shield.jpg" alt="ECS" class="navbar-logo" width="30" height="30">
                <span class="brand-text">Ethio-Cyber Shield</span>
            </a>
            <div class="d-flex align-items-center me-3 d-none d-md-flex">
                <span class="live-pill"><span class="live-pulse"></span>LIVE</span>
            </div>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navMain">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    ${linksHtml}
                </ul>
                <div class="d-flex align-items-center gap-2">
                    <span class="badge bg-dark border border-secondary text-secondary d-none d-lg-inline-flex align-items-center gap-1 font-mono">
                        <i class="bi bi-building"></i> ${escapeHtml(orgId)}
                    </span>
                    <span class="small text-muted d-flex align-items-center gap-1 me-2">
                        <i class="bi bi-person-circle"></i> <strong class="text-light">${escapeHtml(name)}</strong>
                        <span class="badge bg-secondary ms-1">${escapeHtml(role.toUpperCase())}</span>
                    </span>
                    <button class="btn btn-outline-danger btn-sm py-1 px-2" onclick="doLogout()" title="Sign out current device">
                        <i class="bi bi-box-arrow-right me-1"></i>Sign Out
                    </button>
                </div>
            </div>
        </div>
    </nav>`;
}

async function doLogout() {
    try { await API.logout(); } catch(e) {}
    API.clearAuth();
    window.location.href = 'login.html';
}

function severityBadge(sev) {
    const map = { low: 'secondary', medium: 'info', high: 'warning', critical: 'danger' };
    return `<span class="badge bg-${map[sev] || 'secondary'}">${(sev||'').toUpperCase()}</span>`;
}

function statusBadge(status) {
    const map = {
        open: 'danger', investigating: 'warning', contained: 'info',
        resolved: 'success', closed: 'secondary',
        acknowledged: 'info', false_positive: 'secondary',
        unknown: 'secondary', suspicious: 'warning', malicious: 'danger', benign: 'success',
        flagged: 'danger', completed: 'success', pending: 'info'
    };
    return `<span class="badge bg-${map[status] || 'secondary'}">${(status||'').replace('_',' ')}</span>`;
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
// Real-Time Notification & SSE Engine
// -----------------------------------------------------------------------------

let _ecsEventSource = null;
let _ecsReconnectTimer = null;
let _ecsLastSeenAlert = null;
const _seenAlertIds = new Set();

function playAlertTone(severity) {
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        const ctx = new AudioCtx();
        if (ctx.state === 'suspended') {
            ctx.resume();
        }
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        const isHigh = severity === 'critical' || severity === 'high';
        osc.type = isHigh ? 'sawtooth' : 'sine';
        osc.frequency.setValueAtTime(isHigh ? 880 : 587, ctx.currentTime);
        gain.gain.setValueAtTime(0.12, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (isHigh ? 0.35 : 0.2));

        osc.start();
        osc.stop(ctx.currentTime + (isHigh ? 0.4 : 0.25));
    } catch (e) {
        // AudioContext blocked by browser autoplay policy
    }
}

function showInstantAlertNotification(alertData) {
    if (!alertData || !alertData.id) return;
    if (_seenAlertIds.has(alertData.id)) return;
    _seenAlertIds.add(alertData.id);

    // Keep set bounded
    if (_seenAlertIds.size > 200) {
        const first = _seenAlertIds.values().next().value;
        _seenAlertIds.delete(first);
    }

    let container = document.getElementById('ecs-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'ecs-toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '10999';
        document.body.appendChild(container);
    }

    const sev = (alertData.severity || 'medium').toLowerCase();
    const borderMap = { critical: 'danger', high: 'warning', medium: 'info', low: 'secondary' };
    const badgeMap = { critical: 'danger', high: 'warning', medium: 'info', low: 'secondary' };
    const borderClass = borderMap[sev] || 'info';
    const badgeClass = badgeMap[sev] || 'info';

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

function initRealTimeStream() {
    if (typeof API === 'undefined' || !API.isAuthenticated()) return;
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

        _ecsEventSource.onerror = async () => {
            if (_ecsEventSource) {
                try { _ecsEventSource.close(); } catch (e) {}
                _ecsEventSource = null;
            }
            // Check if token was invalidated / superseded by another device
            if (typeof API !== 'undefined' && API.isAuthenticated()) {
                try {
                    await API.me();
                } catch (e) {
                    // API.request handles 401 redirect automatically
                    return;
                }
            }
            if (!_ecsReconnectTimer) {
                _ecsReconnectTimer = setTimeout(() => {
                    _ecsReconnectTimer = null;
                    initRealTimeStream();
                }, 3500);
            }
        };
    } catch (err) {
        console.warn('[ECS Realtime] Connection error, retrying in 5s:', err);
        _ecsReconnectTimer = setTimeout(initRealTimeStream, 5000);
    }
}

window.addEventListener('beforeunload', () => {
    if (_ecsEventSource) {
        try { _ecsEventSource.close(); } catch(e) {}
    }
    if (_ecsReconnectTimer) {
        clearTimeout(_ecsReconnectTimer);
    }
});

// Auto-initialize real-time stream across all pages
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (typeof API !== 'undefined' && API.isAuthenticated()) {
            initRealTimeStream();
        }
    });
} else {
    if (typeof API !== 'undefined' && API.isAuthenticated()) {
        initRealTimeStream();
    }
}
