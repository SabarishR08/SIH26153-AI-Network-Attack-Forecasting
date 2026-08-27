/* ── Events page JS — NetWatch SIH26153 ──────────────────── */

let allEvents     = [];
let filteredEvents = [];
let currentPage   = 1;
const PAGE_SIZE   = 25;

async function loadPageData() {
  try {
    const [aRes, fRes] = await Promise.all([
      fetch('/api/anomalies?limit=1000'),
      fetch('/api/forecast?limit=1000'),
    ]);
    const anomalies = await aRes.json();
    const features  = await fRes.json();

    // Build a lookup: src_ip + window → escalation info
    const escMap = {};
    for (const f of features) {
      if (f.src_ip) {
        const key = f.src_ip;
        if (!escMap[key] || f.escalation_probability > escMap[key].prob) {
          escMap[key] = {
            prob:      f.escalation_probability || 0,
            predicted: f.escalation_predicted   || false,
          };
        }
      }
    }

    // Attach forecast info to anomalies
    allEvents = anomalies.map(a => ({
      ...a,
      _forecast: escMap[a.src_ip] || { prob: 0, predicted: false },
    }));

    updateSummaryCounts();
    applyFilters();
  } catch (err) {
    console.error('Events load failed:', err);
  }
}

function updateSummaryCounts() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const e of allEvents) {
    const s = (e.severity || 'MEDIUM').toUpperCase();
    if (s in counts) counts[s]++;
  }
  document.getElementById('cnt-critical').textContent = counts.CRITICAL;
  document.getElementById('cnt-high').textContent     = counts.HIGH;
  document.getElementById('cnt-medium').textContent   = counts.MEDIUM;
  document.getElementById('cnt-low').textContent      = counts.LOW;
}

function applyFilters() {
  const sev  = document.getElementById('filter-severity').value;
  const type = document.getElementById('filter-type').value;

  filteredEvents = allEvents.filter(e => {
    if (sev  && (e.severity   || '').toUpperCase() !== sev)  return false;
    if (type && (e.anomaly_type || '') !== type) return false;
    return true;
  });

  currentPage = 1;
  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('events-tbody');
  const start = (currentPage - 1) * PAGE_SIZE;
  const page  = filteredEvents.slice(start, start + PAGE_SIZE);

  document.getElementById('events-count').textContent =
    `${filteredEvents.length} event${filteredEvents.length !== 1 ? 's' : ''}`;
  document.getElementById('page-indicator').textContent =
    `Page ${currentPage} / ${Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE))}`;

  if (!page.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="py-10 text-center text-muted">No events match the current filter</td></tr>';
    return;
  }

  tbody.innerHTML = page.map((a, idx) => {
    const f   = a._forecast;
    const fHtml = f.predicted
      ? `${fmtProb(f.prob)} <span class="text-critical font-semibold">⚠ Escalation</span>`
      : fmtProb(f.prob);

    const detail = a.ports_scanned
      ? `${a.port_count || 0} ports`
      : a.failed_attempts
        ? `${a.failed_attempts} attempts`
        : a.connections_in_window
          ? `${a.connections_in_window} conns`
          : '—';

    return `
      <tr class="fade-in hover:bg-border/30" data-idx="${start + idx}" style="cursor:pointer">
        <td class="px-4 py-2.5 text-muted whitespace-nowrap">${fmtTime(a.timestamp)}</td>
        <td class="px-4 py-2.5 text-white font-medium">${a.anomaly_type || '—'}</td>
        <td class="px-4 py-2.5 font-mono text-xs text-white">${a.src_ip || '—'}</td>
        <td class="px-4 py-2.5 font-mono text-xs">${a.dst_ip || '—'}${a.dst_port ? ':' + a.dst_port : ''}</td>
        <td class="px-4 py-2.5">${sevPill(a.severity)}</td>
        <td class="px-4 py-2.5 text-muted">${a.confidence ? Math.round(a.confidence * 100) + '%' : '—'}</td>
        <td class="px-4 py-2.5">${fHtml}</td>
        <td class="px-4 py-2.5 text-muted">${detail}</td>
      </tr>`;
  }).join('');

  // Click handler
  tbody.querySelectorAll('tr[data-idx]').forEach(row => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.getAttribute('data-idx'));
      openDrawer(filteredEvents[idx]);
    });
  });
}

function openDrawer(event) {
  const content = document.getElementById('drawer-content');
  const f = event._forecast || {};

  const fields = [
    ['Anomaly ID',    event.anomaly_id],
    ['Type',          event.anomaly_type],
    ['Source IP',     event.src_ip],
    ['Destination IP',event.dst_ip],
    ['Destination Port', event.dst_port],
    ['Severity',      event.severity],
    ['Confidence',    event.confidence ? Math.round(event.confidence * 100) + '%' : null],
    ['Timestamp',     fmtTime(event.timestamp)],
    ['Ports Scanned', event.ports_scanned ? event.ports_scanned.join(', ') : null],
    ['Failed Attempts', event.failed_attempts],
    ['Service',       event.service],
    ['Connections in Window', event.connections_in_window],
    ['--- Model B Forecast ---', null],
    ['Escalation Probability', f.prob !== undefined ? fmtPct(f.prob) : null],
    ['Escalation Predicted',   f.predicted !== undefined ? (f.predicted ? '⚠ Yes' : 'No') : null],
  ];

  content.innerHTML = fields
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => {
      if (k.startsWith('---')) return `<p class="text-muted font-semibold pt-2 border-t border-border">${k.replace(/---/g,'').trim()}</p>`;
      return `<div class="flex justify-between gap-2">
        <span class="text-muted">${k}</span>
        <span class="text-white text-right break-all font-mono">${v}</span>
      </div>`;
    }).join('');

  document.getElementById('event-drawer').classList.remove('hidden');
  document.getElementById('drawer-overlay').classList.remove('hidden');
}

function closeDrawer() {
  document.getElementById('event-drawer').classList.add('hidden');
  document.getElementById('drawer-overlay').classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  loadPageData();

  document.getElementById('filter-severity').addEventListener('change', applyFilters);
  document.getElementById('filter-type').addEventListener('change', applyFilters);
  document.getElementById('refresh-events').addEventListener('click', loadPageData);

  document.getElementById('prev-page').addEventListener('click', () => {
    if (currentPage > 1) { currentPage--; renderTable(); }
  });
  document.getElementById('next-page').addEventListener('click', () => {
    const maxPage = Math.ceil(filteredEvents.length / PAGE_SIZE);
    if (currentPage < maxPage) { currentPage++; renderTable(); }
  });

  setInterval(loadPageData, 20000);
});
