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
    const name = user ? user.full_name : 'User';
    const role = user ? user.role : '';

    return `
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-success">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold text-success d-flex align-items-center gap-2" href="dashboard.html">
                <img src="assets/logo-shield.jpg" alt="ECS" class="navbar-logo" width="36" height="36">
                <span>Ethio-Cyber Shield</span>
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navMain">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link ${activePage==='dashboard'?'active':''}" href="dashboard.html">Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='incidents'?'active':''}" href="incidents.html">Incidents</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='indicators'?'active':''}" href="indicators.html">Indicators</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='fraud'?'active':''}" href="fraud.html">Fraud</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='live'?'active':''}" href="live-threats.html"><i class="bi bi-activity"></i> Live Threats</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='watchlists'?'active':''}" href="watchlists.html">Watchlists</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='alerts'?'active':''}" href="alerts.html">Alerts</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='reports'?'active':''}" href="reports.html">Reports</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='settings'?'active':''}" href="settings.html">Settings</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='users'?'active':''}" href="users.html">Users</a></li>
                    <li class="nav-item"><a class="nav-link ${activePage==='audit'?'active':''}" href="audit.html">Audit Log</a></li>
                </ul>
                <div class="d-flex align-items-center text-light">
                    <span class="me-3 small"><i class="bi bi-person-badge"></i> ${name} <span class="badge bg-secondary">${role}</span></span>
                    <button class="btn btn-outline-danger btn-sm" onclick="doLogout()">Logout</button>
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
