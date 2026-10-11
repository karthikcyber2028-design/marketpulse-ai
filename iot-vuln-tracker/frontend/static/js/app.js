const API = '/api/v1';
let currentPage = 1;
let searchTimeout = null;
let trendChart = null;
let riskChart = null;

// --- Navigation ---
function showSection(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    document.getElementById(`section-${section}`).classList.add('active');
    document.querySelector(`[data-section="${section}"]`)?.classList.add('active');

    if (section === 'dashboard') refreshDashboard();
    else if (section === 'vulnerabilities') loadVulnerabilities();
    else if (section === 'manufacturers') loadManufacturers();
    else if (section === 'alerts') loadAlerts();
    else if (section === 'integrations') showTab('webhooks');
}

// --- Toast ---
function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// --- API Helpers ---
async function api(path, opts = {}) {
    try {
        const resp = await fetch(`${API}${path}`, {
            headers: { 'Content-Type': 'application/json', ...opts.headers },
            ...opts,
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Request failed');
        return data;
    } catch (e) {
        showToast(e.message, 'error');
        throw e;
    }
}

// --- Dashboard ---
async function refreshDashboard() {
    try {
        const summary = await api('/dashboard/summary');
        document.getElementById('stat-total').textContent = summary.total_vulnerabilities.toLocaleString();
        document.getElementById('stat-critical').textContent = summary.critical_vulnerabilities;
        document.getElementById('stat-high').textContent = summary.high_vulnerabilities;
        document.getElementById('stat-medium').textContent = summary.medium_vulnerabilities;
        document.getElementById('stat-active-alerts').textContent = summary.active_alerts;
        document.getElementById('stat-manufacturers').textContent = summary.manufacturers_tracked;
        document.getElementById('stat-devices').textContent = summary.devices_tracked;
        document.getElementById('stat-exploited').textContent = summary.actively_exploited;
    } catch (e) { /* handled */ }

    try {
        const rankings = await api('/dashboard/manufacturer-rankings?limit=10');
        const tbody = document.querySelector('#rankings-table tbody');
        tbody.innerHTML = rankings.map((r, i) => `
            <tr>
                <td>${i + 1}</td>
                <td><strong>${r.manufacturer_name}</strong></td>
                <td>
                    <div class="score-bar">
                        <div class="score-bar-bg">
                            <div class="score-bar-fill" style="width:${r.security_posture_score}%;background:${getScoreColor(r.security_posture_score)}"></div>
                        </div>
                        <span>${r.security_posture_score?.toFixed(1) || '-'}</span>
                    </div>
                </td>
                <td>${r.total_vulnerabilities}</td>
                <td>${r.critical_vulnerabilities}</td>
                <td>${r.avg_time_to_patch_hours ? r.avg_time_to_patch_hours.toFixed(0) + 'h' : '-'}</td>
                <td><span class="badge badge-${getRatingBadge(r.risk_rating)}">${r.risk_rating || 'N/A'}</span></td>
            </tr>
        `).join('');
    } catch (e) { /* handled */ }

    try {
        const trends = await api('/dashboard/vulnerability-trends?days=90&group_by=day');
        renderTrendChart(trends);
    } catch (e) { /* handled */ }

    try {
        const dist = await api('/dashboard/risk-distribution');
        renderRiskChart(dist);
    } catch (e) { /* handled */ }

    try {
        const compliance = await api('/dashboard/compliance-mapping');
        renderCompliance(compliance);
    } catch (e) { /* handled */ }
}

function getScoreColor(score) {
    if (score >= 80) return '#2ed573';
    if (score >= 60) return '#ffc048';
    if (score >= 40) return '#ff8a50';
    return '#ff4757';
}

function getRatingBadge(rating) {
    const map = { exemplary: 'low', good: 'info', average: 'medium', poor: 'high', critical: 'critical' };
    return map[rating] || 'info';
}

function renderTrendChart(data) {
    const ctx = document.getElementById('trend-chart');
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.date),
            datasets: [
                { label: 'Critical', data: data.map(d => d.critical), backgroundColor: '#ff4757' },
                { label: 'High', data: data.map(d => d.high), backgroundColor: '#ff8a50' },
                { label: 'Medium', data: data.map(d => d.medium), backgroundColor: '#ffc048' },
                { label: 'Low', data: data.map(d => d.low), backgroundColor: '#2ed573' },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, grid: { color: '#2a2d3a' }, ticks: { color: '#5f6377', maxTicksLimit: 15 } },
                y: { stacked: true, grid: { color: '#2a2d3a' }, ticks: { color: '#5f6377' } },
            },
            plugins: { legend: { labels: { color: '#8b8fa3' } } },
        },
    });
}

function renderRiskChart(data) {
    const ctx = document.getElementById('risk-chart');
    if (riskChart) riskChart.destroy();
    const colors = ['#ff4757', '#ff8a50', '#ffc048', '#2ed573', '#5f6377'];
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.range),
            datasets: [{ data: data.map(d => d.count), backgroundColor: colors }],
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom', labels: { color: '#8b8fa3' } } },
        },
    });
}

function renderCompliance(data) {
    const container = document.getElementById('compliance-mapping');
    container.innerHTML = '<div class="compliance-grid">' +
        Object.entries(data).map(([framework, sections]) => {
            const title = framework.replace(/_/g, ' ').toUpperCase();
            const items = Object.entries(sections).map(([key, section]) =>
                Object.entries(section).map(([k, v]) => `
                    <div class="compliance-item">
                        <span class="label">${k.replace(/_/g, ' ')}</span>
                        <span class="value">${typeof v === 'number' ? v.toLocaleString() : v}</span>
                    </div>
                `).join('')
            ).join('');
            return `<div class="compliance-card"><h4>${title}</h4>${items}</div>`;
        }).join('') +
    '</div>';
}

// --- Vulnerabilities ---
async function loadVulnerabilities(page = 1) {
    currentPage = page;
    const severity = document.getElementById('vuln-severity-filter')?.value || '';
    const status = document.getElementById('vuln-status-filter')?.value || '';
    const search = document.getElementById('vuln-search')?.value || '';

    const params = new URLSearchParams({ page, page_size: 20 });
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    if (search) params.set('search', search);

    try {
        const data = await api(`/vulnerabilities?${params}`);
        const tbody = document.querySelector('#vuln-table tbody');
        tbody.innerHTML = data.items.map(v => `
            <tr>
                <td><strong>${v.cve_id}</strong></td>
                <td class="muted" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.cve_description}</td>
                <td><span class="badge badge-${v.severity}">${v.severity}</span></td>
                <td><strong>${v.composite_risk_score?.toFixed(1) || '-'}</strong></td>
                <td>${v.cvss_v3_score || v.cvss_v2_score || '-'}</td>
                <td><span class="badge badge-${statusBadge(v.status)}">${v.status}</span></td>
                <td>${v.exploit_available ? '<span class="exploit-icon">EXP</span>' : '<span class="muted">-</span>'}</td>
                <td class="muted">${v.published_date ? new Date(v.published_date).toLocaleDateString() : '-'}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="viewVulnerability(${v.id})">View</button>
                </td>
            </tr>
        `).join('');

        renderPagination('vuln-pagination', data.page, data.pages, loadVulnerabilities);
    } catch (e) { /* handled */ }
}

function statusBadge(status) {
    const map = { analyzing: 'info', unpatched: 'critical', patched: 'low', partially_patched: 'medium', disputed: 'medium', retracted: 'info' };
    return map[status] || 'info';
}

function renderPagination(containerId, current, total, callback) {
    const container = document.getElementById(containerId);
    if (!container || total <= 1) { if (container) container.innerHTML = ''; return; }
    let html = '';
    if (current > 1) html += `<button onclick="${callback.name}(${current - 1})">Prev</button>`;
    for (let i = Math.max(1, current - 2); i <= Math.min(total, current + 2); i++) {
        html += `<button class="${i === current ? 'active' : ''}" onclick="${callback.name}(${i})">${i}</button>`;
    }
    if (current < total) html += `<button onclick="${callback.name}(${current + 1})">Next</button>`;
    container.innerHTML = html;
}

function debounceSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => loadVulnerabilities(1), 300);
}

async function viewVulnerability(id) {
    try {
        const v = await api(`/vulnerabilities/${id}`);
        let scoreDetail = '';
        try {
            const score = await api(`/vulnerabilities/${id}/score`);
            scoreDetail = `
                <div style="margin-top:16px">
                    <h4 style="color:var(--accent);margin-bottom:8px">Risk Score Breakdown</h4>
                    <div class="compliance-item"><span class="label">CVSS</span><span class="value">${score.cvss_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Exploit Availability</span><span class="value">${score.exploit_availability_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Wild Exploitation</span><span class="value">${score.wild_exploitation_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Manufacturer Response</span><span class="value">${score.manufacturer_response_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Device Population</span><span class="value">${score.device_population_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Deployment Context</span><span class="value">${score.deployment_context_component?.toFixed(1)}</span></div>
                    <div class="compliance-item"><span class="label">Age</span><span class="value">${score.age_component?.toFixed(1)}</span></div>
                </div>`;
        } catch (e) {}

        document.getElementById('modal-title').textContent = v.cve_id;
        document.getElementById('modal-body').innerHTML = `
            <div><strong>Severity:</strong> <span class="badge badge-${v.severity}">${v.severity}</span></div>
            <div style="margin-top:8px"><strong>Risk Score:</strong> ${v.composite_risk_score?.toFixed(2) || 'N/A'} / 10.0</div>
            <div style="margin-top:8px"><strong>CVSS v3:</strong> ${v.cvss_v3_score || 'N/A'} | <strong>CVSS v2:</strong> ${v.cvss_v2_score || 'N/A'}</div>
            <div style="margin-top:8px"><strong>Status:</strong> ${v.status}</div>
            <div style="margin-top:8px"><strong>Exploit Available:</strong> ${v.exploit_available ? 'Yes' : 'No'}</div>
            <div style="margin-top:8px"><strong>Actively Exploited:</strong> ${v.actively_exploited ? 'Yes' : 'No'}</div>
            <div style="margin-top:8px"><strong>Confidence:</strong> ${(v.confidence_score * 100).toFixed(0)}%</div>
            <div style="margin-top:8px"><strong>Published:</strong> ${v.published_date ? new Date(v.published_date).toLocaleDateString() : 'N/A'}</div>
            <div style="margin-top:12px"><strong>Description:</strong><p style="color:var(--text-secondary);font-size:13px;margin-top:4px">${v.cve_description}</p></div>
            ${v.affected_product_names ? `<div style="margin-top:8px"><strong>Affected Products:</strong> ${v.affected_product_names}</div>` : ''}
            ${v.cwe_id ? `<div style="margin-top:8px"><strong>CWE:</strong> ${v.cwe_id}</div>` : ''}
            ${scoreDetail}
        `;
        document.getElementById('modal-overlay').style.display = 'flex';
    } catch (e) { /* handled */ }
}

function closeModal() {
    document.getElementById('modal-overlay').style.display = 'none';
}

// --- Manufacturers ---
async function loadManufacturers() {
    try {
        const data = await api('/manufacturers?page_size=50&sort_by=security_posture_score&sort_order=asc');
        const tbody = document.querySelector('#mfg-table tbody');
        tbody.innerHTML = data.items.map(m => `
            <tr>
                <td><strong>${m.name}</strong></td>
                <td>
                    <div class="score-bar">
                        <div class="score-bar-bg">
                            <div class="score-bar-fill" style="width:${m.security_posture_score}%;background:${getScoreColor(m.security_posture_score)}"></div>
                        </div>
                        <span>${m.security_posture_score?.toFixed(1) || '50.0'}</span>
                    </div>
                </td>
                <td>${m.total_vulnerabilities}</td>
                <td>${m.critical_vulnerabilities}</td>
                <td>${m.active_vulnerabilities}</td>
                <td>${m.avg_time_to_patch_hours ? m.avg_time_to_patch_hours.toFixed(0) + 'h' : '-'}</td>
                <td>${m.patch_availability_rate ? m.patch_availability_rate.toFixed(0) + '%' : '-'}</td>
                <td><span class="badge badge-${getRatingBadge(m.risk_rating)}">${m.risk_rating || 'N/A'}</span></td>
                <td><button class="btn btn-sm btn-outline" onclick="showManufacturerDetail(${m.id})">View</button></td>
            </tr>
        `).join('');
    } catch (e) { /* handled */ }
}

async function showManufacturerDetail(id) {
    try {
        const m = await api(`/manufacturers/${id}`);
        document.getElementById('modal-title').textContent = m.name;
        document.getElementById('modal-body').innerHTML = `
            <div><strong>Posture Score:</strong> ${m.security_posture_score?.toFixed(1) || 'N/A'} / 100</div>
            <div><strong>Rating:</strong> <span class="badge badge-${getRatingBadge(m.risk_rating)}">${m.risk_rating || 'N/A'}</span></div>
            <div><strong>Total Vulnerabilities:</strong> ${m.total_vulnerabilities}</div>
            <div><strong>Critical:</strong> ${m.critical_vulnerabilities}</div>
            <div><strong>Active:</strong> ${m.active_vulnerabilities}</div>
            <div><strong>Avg Time to Patch:</strong> ${m.avg_time_to_patch_hours ? m.avg_time_to_patch_hours.toFixed(0) + 'h' : 'N/A'}</div>
            <div><strong>Patch Availability Rate:</strong> ${m.patch_availability_rate ? m.patch_availability_rate.toFixed(0) + '%' : 'N/A'}</div>
            ${m.website ? `<div><strong>Website:</strong> <a href="${m.website}" target="_blank" style="color:var(--accent)">${m.website}</a></div>` : ''}
            ${m.headquarters_country ? `<div><strong>Country:</strong> ${m.headquarters_country}</div>` : ''}
        `;
        document.getElementById('modal-overlay').style.display = 'flex';
    } catch (e) { /* handled */ }
}

async function showAddManufacturer() {
    document.getElementById('modal-title').textContent = 'Add Manufacturer';
    document.getElementById('modal-body').innerHTML = `
        <label>Name</label><input id="mfg-name" type="text" placeholder="e.g., Siemens">
        <label>Website</label><input id="mfg-website" type="text" placeholder="https://...">
        <label>Country</label><input id="mfg-country" type="text" placeholder="e.g., Germany">
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="submitManufacturer()">Create</button></div>
    `;
    document.getElementById('modal-overlay').style.display = 'flex';
}

async function submitManufacturer() {
    const name = document.getElementById('mfg-name').value;
    if (!name) return showToast('Name required', 'error');
    await api('/manufacturers', {
        method: 'POST',
        body: JSON.stringify({
            name,
            website: document.getElementById('mfg-website').value || null,
            headquarters_country: document.getElementById('mfg-country').value || null,
        }),
    });
    showToast('Manufacturer created', 'success');
    closeModal();
    loadManufacturers();
}

async function rescoreManufacturers() {
    await api('/manufacturers/rescore', { method: 'POST' });
    showToast('Scores recalculated', 'success');
    loadManufacturers();
}

// --- Alerts ---
async function loadAlerts() {
    try {
        const summary = await api('/alerts/summary');
        const container = document.getElementById('alert-summary');
        container.innerHTML = `
            <div class="alert-stat"><div class="count" style="color:var(--text-primary)">${summary.total}</div><div class="label">Total Alerts</div></div>
            <div class="alert-stat"><div class="count" style="color:var(--danger)">${summary.active}</div><div class="label">Active</div></div>
            <div class="alert-stat"><div class="count" style="color:var(--critical)">${summary.by_severity?.critical || 0}</div><div class="label">Critical</div></div>
            <div class="alert-stat"><div class="count" style="color:var(--high)">${summary.by_severity?.high || 0}</div><div class="label">High</div></div>
            <div class="alert-stat"><div class="count" style="color:var(--medium)">${summary.by_severity?.medium || 0}</div><div class="label">Medium</div></div>
        `;
    } catch (e) { /* handled */ }

    try {
        const data = await api('/alerts?page_size=50');
        const tbody = document.querySelector('#alert-table tbody');
        tbody.innerHTML = data.items.map(a => `
            <tr>
                <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
                <td>${a.title}</td>
                <td><span class="badge badge-${a.status === 'new' ? 'critical' : a.status === 'resolved' ? 'low' : 'info'}">${a.status}</span></td>
                <td>${a.assigned_to || '<span class="muted">Unassigned</span>'}</td>
                <td class="muted">${new Date(a.created_at).toLocaleString()}</td>
                <td>
                    ${a.status !== 'resolved' ? `<button class="btn btn-sm btn-outline" onclick="acknowledgeAlert(${a.id})">Ack</button>
                    <button class="btn btn-sm btn-outline" onclick="resolveAlert(${a.id})">Resolve</button>` : ''}
                </td>
            </tr>
        `).join('');
    } catch (e) { /* handled */ }
}

async function acknowledgeAlert(id) {
    await api(`/alerts/${id}/acknowledge`, { method: 'PATCH' });
    showToast('Alert acknowledged', 'success');
    loadAlerts();
}

async function resolveAlert(id) {
    await api(`/alerts/${id}/resolve`, { method: 'PATCH' });
    showToast('Alert resolved', 'success');
    loadAlerts();
}

// --- Integrations ---
async function showTab(tab) {
    document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
    event?.target?.classList?.add('active');

    const container = document.getElementById('integrations-content');

    if (tab === 'webhooks') {
        const data = await api('/webhooks');
        container.innerHTML = `<h3>Webhook Endpoints</h3>` + (data.length === 0 ? '<p class="muted">No webhooks configured</p>' :
            `<table><thead><tr><th>Name</th><th>URL</th><th>Active</th><th>Last Triggered</th><th>Failures</th><th>Actions</th></tr></thead><tbody>` +
            data.map(w => `<tr><td>${w.name}</td><td class="muted" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${w.url}</td><td>${w.is_active ? 'Yes' : 'No'}</td><td>${w.last_triggered_at ? new Date(w.last_triggered_at).toLocaleString() : 'Never'}</td><td>${w.failure_count}</td><td><button class="btn btn-sm btn-outline" onclick="testWebhook(${w.id})">Test</button></td></tr>`).join('') +
            `</tbody></table>`);
    } else if (tab === 'siem') {
        const data = await api('/siem');
        container.innerHTML = `<h3>SIEM Integrations</h3>` + (data.length === 0 ? '<p class="muted">No SIEM integrations configured</p>' :
            `<table><thead><tr><th>Name</th><th>Type</th><th>Active</th><th>Last Synced</th></tr></thead><tbody>` +
            data.map(s => `<tr><td>${s.name}</td><td>${s.siem_type}</td><td>${s.is_active ? 'Yes' : 'No'}</td><td>${s.last_synced_at ? new Date(s.last_synced_at).toLocaleString() : 'Never'}</td></tr>`).join('') +
            `</tbody></table>`);
    } else if (tab === 'ticketing') {
        const data = await api('/ticketing');
        container.innerHTML = `<h3>Ticketing Integrations</h3>` + (data.length === 0 ? '<p class="muted">No ticketing integrations configured</p>' :
            `<table><thead><tr><th>Name</th><th>Platform</th><th>Active</th><th>Auto-Create</th></tr></thead><tbody>` +
            data.map(t => `<tr><td>${t.name}</td><td>${t.platform}</td><td>${t.is_active ? 'Yes' : 'No'}</td><td>${t.auto_create_tickets ? 'Yes' : 'No'}</td></tr>`).join('') +
            `</tbody></table>`);
    } else if (tab === 'asset-mgmt') {
        const data = await api('/asset-management');
        container.innerHTML = `<h3>Asset Management Syncs</h3>` + (data.length === 0 ? '<p class="muted">No asset management integrations configured</p>' :
            `<table><thead><tr><th>Name</th><th>Platform</th><th>Active</th><th>Devices</th><th>Last Synced</th></tr></thead><tbody>` +
            data.map(a => `<tr><td>${a.name}</td><td>${a.platform}</td><td>${a.is_active ? 'Yes' : 'No'}</td><td>${a.device_count}</td><td>${a.last_synced_at ? new Date(a.last_synced_at).toLocaleString() : 'Never'}</td></tr>`).join('') +
            `</tbody></table>`);
    } else if (tab === 'data-sources') {
        const data = await api('/data-sources');
        container.innerHTML = `<h3>Vulnerability Data Sources</h3>` +
            `<table><thead><tr><th>Name</th><th>Type</th><th>Active</th><th>Reliability</th><th>Last Synced</th></tr></thead><tbody>` +
            data.map(s => `<tr><td>${s.name}</td><td>${s.source_type}</td><td>${s.is_active ? 'Yes' : 'No'}</td><td>${(s.reliability_score * 100).toFixed(0)}%</td><td>${s.last_synced_at ? new Date(s.last_synced_at).toLocaleString() : 'Never'}</td></tr>`).join('') +
            `</tbody></table>`;
    }
}

async function testWebhook(id) {
    await api(`/webhooks/${id}/test`, { method: 'POST' });
    showToast('Webhook test sent', 'info');
}

// --- Sync ---
async function triggerSync(source) {
    showToast(`Triggering ${source} sync...`, 'info');
    try {
        const result = await api(`/sync/${source}`, { method: 'POST' });
        showToast(result.message, 'success');
        refreshDashboard();
    } catch (e) { /* handled */ }
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    refreshDashboard();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});
