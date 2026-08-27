/* ── Overview page JS — NetWatch SIH26153 ─────────────────── */

const PLOTLY_LAYOUT_BASE = {
  paper_bgcolor: 'transparent',
  plot_bgcolor:  'transparent',
  margin:        { t: 8, r: 8, b: 30, l: 36 },
  font:          { family: 'Inter, sans-serif', size: 11, color: '#8b949e' },
  showlegend:    false,
};

async function loadPageData() {
  try {
    const res  = await fetch('/api/dashboard');
    const d    = await res.json();
    renderStats(d);
    renderTimeline(d.anomalies?.timeline || []);
    renderSeverityDonut(d.anomalies?.by_severity || {});
    renderProtocolBar(d.traffic?.protocols || {});
    renderStagesBar(d.killchain?.stages || {});
    renderRecentAnomalies();
    document.getElementById('last-updated').textContent =
      'Updated ' + fmtTime(d.generated_at);
  } catch (err) {
    console.error('Dashboard load failed:', err);
  }
}

function renderStats(d) {
  const t = d.traffic   || {};
  const a = d.anomalies || {};
  const f = d.forecast  || {};
  const k = d.killchain || {};
  const ma = d.model_a  || {};

  document.getElementById('stat-packets').textContent = (t.total_packets || 0).toLocaleString();
  document.getElementById('stat-ips').textContent     = `${t.unique_src_ips || 0} unique sources`;

  document.getElementById('stat-anomalies').textContent    = (a.total || 0).toLocaleString();
  const typeStr = Object.entries(a.by_type || {})
    .sort((x,y) => y[1]-x[1]).slice(0,2)
    .map(([k,v]) => `${k} (${v})`).join(', ');
  document.getElementById('stat-anomaly-types').textContent = typeStr || '—';

  document.getElementById('stat-escalations').textContent = f.escalation_predicted || '0';
  document.getElementById('stat-esc-prob').textContent    =
    `avg prob ${fmtPct(f.avg_escalation_prob)}`;

  document.getElementById('stat-incidents').textContent = k.total_incidents || 0;
  document.getElementById('stat-mitre').textContent     = `${(k.mitre_techniques || []).length} MITRE techniques`;

  // Model A
  document.getElementById('model-a-name').textContent =
    `PS40 · ${ma.best_model || 'RandomForest / GradientBoosting'}`;
  document.getElementById('model-a-acc').textContent =
    ma.accuracy ? fmtPct(ma.accuracy) : '—';
  document.getElementById('model-a-f1').textContent  =
    ma.f1       ? Number(ma.f1).toFixed(4)    : '—';
  document.getElementById('model-a-auc').textContent =
    ma.roc_auc  ? Number(ma.roc_auc).toFixed(4) : '—';

  // Model B
  const mb = document.getElementById('model-b-badge');
  if (f.enabled) {
    mb.textContent = 'Active';
    mb.className   = 'model-badge bg-low/20 text-low border border-low/30';
  } else {
    mb.textContent = 'Disabled';
    mb.className   = 'model-badge bg-border text-muted border border-border';
  }
  document.getElementById('model-b-windows').textContent = f.total_windows || '—';
  document.getElementById('model-b-esc').textContent     = f.escalation_predicted ?? '—';
  document.getElementById('model-b-prob').textContent    = fmtPct(f.avg_escalation_prob);

  // Status badge
  const badge = document.getElementById('pipeline-status-badge');
  if ((a.total || 0) > 0) {
    badge.textContent  = 'Data loaded';
    badge.className    = 'text-xs px-2 py-1 rounded-full bg-low/20 text-low border border-low/30';
  } else {
    badge.textContent  = 'No data yet — run pipeline';
    badge.className    = 'text-xs px-2 py-1 rounded-full bg-border text-muted';
  }
}

function renderTimeline(timeline) {
  const el = document.getElementById('chart-timeline');
  if (!el) return;
  if (!timeline.length) { el.innerHTML = '<p class="text-muted text-xs text-center pt-16">No data</p>'; return; }

  const x = timeline.map(r => r.t);
  const y = timeline.map(r => r.v);

  Plotly.newPlot(el, [{
    x, y,
    type: 'scatter', mode: 'lines+markers',
    line:    { color: '#58a6ff', width: 2, shape: 'spline' },
    marker:  { color: '#58a6ff', size: 4 },
    fill:    'tozeroy',
    fillcolor: 'rgba(88,166,255,0.08)',
    hovertemplate: '%{x}<br>%{y} anomalies<extra></extra>',
  }], {
    ...PLOTLY_LAYOUT_BASE,
    xaxis: { showgrid: false, tickfont: { size: 9 }, type: 'category' },
    yaxis: { gridcolor: '#21262d', tickfont: { size: 9 }, zeroline: false },
  }, { responsive: true, displayModeBar: false });
}

function renderSeverityDonut(bySev) {
  const el = document.getElementById('chart-severity');
  if (!el) return;
  const labels = ['CRITICAL','HIGH','MEDIUM','LOW'];
  const vals   = labels.map(l => bySev[l] || 0);
  if (vals.every(v => v === 0)) {
    el.innerHTML = '<p class="text-muted text-xs text-center pt-16">No data</p>'; return;
  }

  Plotly.newPlot(el, [{
    labels, values: vals, type: 'pie', hole: 0.62,
    marker: { colors: ['#f85149','#e3b341','#58a6ff','#3fb950'] },
    textinfo: 'none',
    hovertemplate: '%{label}: %{value}<extra></extra>',
  }], {
    ...PLOTLY_LAYOUT_BASE,
    margin: { t: 8, r: 8, b: 8, l: 8 },
    showlegend: true,
    legend: { font: { size: 10, color: '#8b949e' }, orientation: 'v', x: 0.85, y: 0.5 },
  }, { responsive: true, displayModeBar: false });
}

function renderProtocolBar(protocols) {
  const el = document.getElementById('chart-protocols');
  if (!el) return;
  const entries = Object.entries(protocols).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<p class="text-muted text-xs text-center pt-14">No data</p>'; return; }

  Plotly.newPlot(el, [{
    x: entries.map(e => e[0]),
    y: entries.map(e => e[1]),
    type: 'bar',
    marker: { color: '#238636' },
    hovertemplate: '%{x}: %{y}<extra></extra>',
  }], {
    ...PLOTLY_LAYOUT_BASE,
    xaxis: { showgrid: false },
    yaxis: { gridcolor: '#21262d', zeroline: false },
  }, { responsive: true, displayModeBar: false });
}

function renderStagesBar(stages) {
  const el = document.getElementById('chart-stages');
  if (!el) return;
  const entries = Object.entries(stages).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<p class="text-muted text-xs text-center pt-14">No data</p>'; return; }

  Plotly.newPlot(el, [{
    y: entries.map(e => e[0]),
    x: entries.map(e => e[1]),
    type: 'bar', orientation: 'h',
    marker: { color: '#58a6ff' },
    hovertemplate: '%{y}: %{x}<extra></extra>',
  }], {
    ...PLOTLY_LAYOUT_BASE,
    margin: { t: 8, r: 8, b: 30, l: 120 },
    xaxis: { gridcolor: '#21262d', zeroline: false },
    yaxis: { showgrid: false },
  }, { responsive: true, displayModeBar: false });
}

async function renderRecentAnomalies() {
  const tbody = document.getElementById('recent-anomalies-tbody');
  if (!tbody) return;
  try {
    const res   = await fetch('/api/anomalies?limit=10');
    const rows  = await res.json();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-muted">No anomalies detected yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.slice(-10).reverse().map(a => `
      <tr class="hover:bg-border/30 cursor-default">
        <td class="py-2 pr-4 text-muted">${fmtTime(a.timestamp)}</td>
        <td class="py-2 pr-4 text-white">${a.anomaly_type || '—'}</td>
        <td class="py-2 pr-4 font-mono text-xs">${a.src_ip || '—'}</td>
        <td class="py-2 pr-4 font-mono text-xs">${a.dst_ip || '—'}</td>
        <td class="py-2">${sevPill(a.severity)}</td>
      </tr>`).join('');
  } catch { tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-muted">Error loading data</td></tr>'; }
}

// Init + auto-refresh every 15s
document.addEventListener('DOMContentLoaded', () => {
  loadPageData();
  setInterval(loadPageData, 15000);
});
