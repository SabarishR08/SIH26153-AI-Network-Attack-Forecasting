/**
 * NetWatch Frontend — Main Dashboard Controller
 * Connects to the backend API and renders dashboard data
 */

// API configuration
const API_BASE = window.location.hostname === 'localhost'
    ? 'http://localhost:5000'
    : 'https://netwatch-sih26153-api.onrender.com';

// State
let dashboardData = null;
let refreshInterval = null;

// ── Initialize ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    console.log('NetWatch frontend initializing...');
    refreshData();
    // Auto-refresh every 30 seconds
    refreshInterval = setInterval(refreshData, 30000);
});

// ── Data Fetching ───────────────────────────────────────────

async function refreshData() {
    try {
        updateStatus('loading');

        const [dashboard, anomalies, forecast] = await Promise.all([
            fetchAPI('/api/dashboard'),
            fetchAPI('/api/anomalies?limit=20'),
            fetchAPI('/api/forecast?limit=10'),
        ]);

        dashboardData = { dashboard, anomalies, forecast };

        renderDashboard(dashboard);
        renderAnomalies(anomalies);
        renderTimeline(dashboard.anomalies.timeline);
        renderSeverityChart(dashboard.anomalies.by_severity);

        updateStatus('connected');
    } catch (error) {
        console.error('Failed to fetch data:', error);
        updateStatus('error');
    }
}

async function fetchAPI(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: {
            'Content-Type': 'application/json',
            'X-Request-ID': generateRequestId(),
        },
    });

    if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
    }

    return response.json();
}

// ── Render Functions ────────────────────────────────────────

function renderDashboard(data) {
    // Traffic stats
    setText('stat-packets', formatNumber(data.traffic.total_packets));
    setText('stat-ips', `${data.traffic.unique_src_ips} unique sources`);

    // Anomaly stats
    setText('stat-anomalies', formatNumber(data.anomalies.total));
    const types = Object.entries(data.anomalies.by_type)
        .map(([type, count]) => `${count} ${type}`)
        .join(', ');
    setText('stat-anomaly-types', types || 'No anomalies');

    // Forecast stats
    setText('stat-escalations', formatNumber(data.forecast.escalation_predicted));
    setText('stat-esc-prob', `avg prob ${data.forecast.avg_escalation_prob}`);

    // Kill chain stats
    setText('stat-incidents', formatNumber(data.killchain.total_incidents));
    setText('stat-mitre', `${data.killchain.mitre_techniques.length} MITRE techniques`);
}

function renderAnomalies(anomalies) {
    const tbody = document.getElementById('anomalies-tbody');
    if (!tbody) return;

    if (!anomalies || anomalies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-muted">No anomalies detected</td></tr>';
        return;
    }

    tbody.innerHTML = anomalies.slice(0, 10).map(anom => `
        <tr class="hover:bg-border/50">
            <td class="py-2 pr-4 text-muted">${formatTime(anom.timestamp)}</td>
            <td class="py-2 pr-4 text-white">${anom.anomaly_type}</td>
            <td class="py-2 pr-4 text-muted font-mono">${anom.src_ip}</td>
            <td class="py-2 pr-4 text-muted font-mono">${anom.dst_ip}</td>
            <td class="py-2">
                <span class="severity-badge severity-${anom.severity.toLowerCase()}">
                    ${anom.severity}
                </span>
            </td>
        </tr>
    `).join('');
}

function renderTimeline(timeline) {
    const container = document.getElementById('chart-timeline');
    if (!container || !timeline || timeline.length === 0) {
        if (container) container.innerHTML = '<p class="text-muted text-sm text-center py-8">No timeline data</p>';
        return;
    }

    const maxVal = Math.max(...timeline.map(t => t.v));
    const barWidth = 100 / timeline.length;

    container.innerHTML = `
        <div class="flex items-end h-full gap-1">
            ${timeline.map((t, i) => `
                <div class="flex-1 bg-accent/30 rounded-t hover:bg-accent/50 transition-colors"
                     style="height: ${(t.v / maxVal) * 100}%"
                     title="${t.t}: ${t.v} anomalies">
                </div>
            `).join('')}
        </div>
        <div class="flex justify-between text-xs text-muted mt-2">
            <span>${timeline[0]?.t?.split('T')[1] || ''}</span>
            <span>${timeline[timeline.length - 1]?.t?.split('T')[1] || ''}</span>
        </div>
    `;
}

function renderSeverityChart(bySeverity) {
    const container = document.getElementById('chart-severity');
    if (!container || !bySeverity) return;

    const total = Object.values(bySeverity).reduce((a, b) => a + b, 0);
    if (total === 0) {
        container.innerHTML = '<p class="text-muted text-sm text-center py-8">No severity data</p>';
        return;
    }

    const colors = {
        CRITICAL: '#ef4444',
        HIGH: '#f97316',
        MEDIUM: '#eab308',
        LOW: '#22c55e',
    };

    container.innerHTML = `
        <div class="space-y-2">
            ${Object.entries(bySeverity).map(([sev, count]) => `
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full" style="background: ${colors[sev]}"></div>
                    <span class="text-xs text-muted w-16">${sev}</span>
                    <div class="flex-1 bg-border rounded-full h-2">
                        <div class="h-2 rounded-full" style="width: ${(count / total) * 100}%; background: ${colors[sev]}"></div>
                    </div>
                    <span class="text-xs text-white w-8 text-right">${count}</span>
                </div>
            `).join('')}
        </div>
    `;
}

// ── Utilities ───────────────────────────────────────────────

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function formatNumber(num) {
    if (num >= 1000) return (num / 1000).toFixed(1) + 'k';
    return num.toString();
}

function formatTime(ts) {
    if (!ts) return '—';
    try {
        const date = new Date(ts);
        if (isNaN(date.getTime())) return ts;
        return date.toLocaleString('en-IN', { hour12: false,
            month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return ts;
    }
}

function updateStatus(status) {
    const badge = document.getElementById('status-badge');
    if (!badge) return;

    const statusMap = {
        loading: { text: 'Loading...', class: 'bg-yellow-500/20 text-yellow-400' },
        connected: { text: 'Connected', class: 'bg-green-500/20 text-green-400' },
        error: { text: 'Error', class: 'bg-red-500/20 text-red-400' },
    };

    const s = statusMap[status] || statusMap.loading;
    badge.textContent = s.text;
    badge.className = `text-xs px-3 py-1 rounded-full ${s.class}`;
}

function generateRequestId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}

// ── Navigation ──────────────────────────────────────────────

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        e.target.classList.add('active');
    });
});
