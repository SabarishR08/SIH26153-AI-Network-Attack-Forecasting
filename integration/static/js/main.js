/* ── Shared utilities — NetWatch SIH26153 ─────────────────── */

const SEV_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
};

function sevPill(sev) {
  const s = (sev || 'MEDIUM').toUpperCase();
  return `<span class="sev-pill ${SEV_CLASS[s] || 'sev-medium'}">${s}</span>`;
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString('en-IN', { hour12: false,
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return iso; }
}

function fmtPct(n) {
  if (n === undefined || n === null) return '—';
  return (Number(n) * 100).toFixed(1) + '%';
}

function fmtProb(prob) {
  const pct = Math.round((prob || 0) * 100);
  const color = pct >= 70 ? '#f85149' : pct >= 50 ? '#e3b341' : '#3fb950';
  return `
    <span style="color:${color};font-weight:600">${pct}%</span>
    <span class="prob-bar-bg">
      <span class="prob-bar-fill" style="width:${pct}%;background:${color}"></span>
    </span>`;
}

/* ── Pipeline trigger (shared across all pages) ──────────── */
document.addEventListener('DOMContentLoaded', () => {
  const btn   = document.getElementById('run-pipeline-btn');
  const toast = document.getElementById('pipeline-toast');
  const icon  = document.getElementById('toast-icon');
  const title = document.getElementById('toast-title');
  const body  = document.getElementById('toast-body');

  if (!btn) return;

  btn.addEventListener('click', async () => {
    toast.classList.remove('hidden');
    icon.textContent  = '⏳';
    title.textContent = 'Running pipeline…';
    body.textContent  = 'Generating traffic, detecting anomalies, forecasting escalations…';
    btn.disabled = true;

    try {
      const res  = await fetch('/api/run-pipeline', { method: 'POST' });
      const data = await res.json();

      if (data.status === 'ok') {
        icon.textContent  = '✅';
        title.textContent = 'Pipeline complete';
        const r = data.result || {};
        const parts = [];
        if (r.step1_traffic?.packets) parts.push(`${r.step1_traffic.packets} packets`);
        if (r.step2_anomalies?.total !== undefined) parts.push(`${r.step2_anomalies.total} anomalies`);
        if (r.step5_killchain?.incidents !== undefined) parts.push(`${r.step5_killchain.incidents} incidents`);
        body.textContent = parts.join(' · ') || `Done in ${r.elapsed_sec}s`;
        // Refresh whichever page-specific loader exists
        if (typeof loadPageData === 'function') loadPageData();
      } else {
        icon.textContent  = '❌';
        title.textContent = 'Pipeline error';
        body.textContent  = data.error || 'Unknown error — check server logs.';
      }
    } catch (err) {
      icon.textContent  = '❌';
      title.textContent = 'Request failed';
      body.textContent  = err.message;
    } finally {
      btn.disabled = false;
      setTimeout(() => toast.classList.add('hidden'), 8000);
    }
  });
});
