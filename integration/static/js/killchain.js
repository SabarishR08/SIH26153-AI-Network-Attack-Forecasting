/* ── Kill Chain page JS — NetWatch SIH26153 ──────────────── */

const PRIORITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function priorityClass(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

async function loadPageData() {
  try {
    const res       = await fetch('/api/incidents');
    const incidents = await res.json();
    renderIncidents(incidents);
    renderMitreCoverage(incidents);
  } catch (err) {
    console.error('Killchain load failed:', err);
  }
}

function renderIncidents(incidents) {
  const list       = document.getElementById('incident-list');
  const noIncidents = document.getElementById('no-incidents');
  const tpl        = document.getElementById('incident-tpl');

  list.innerHTML = '';

  if (!incidents || !incidents.length) {
    list.classList.add('hidden');
    noIncidents.classList.remove('hidden');
    return;
  }

  noIncidents.classList.add('hidden');
  list.classList.remove('hidden');

  // Sort by risk_score desc
  const sorted = [...incidents].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  for (const inc of sorted) {
    const score    = inc.risk_score || 0;
    const priority = priorityClass(score);
    const mitre    = inc.mitre || {};

    const card = tpl.content.cloneNode(true);
    const el   = card.querySelector('div');

    const priorityEl = el.querySelector('.incident-priority');
    priorityEl.textContent = priority;
    priorityEl.className  += ` priority-${priority} px-2 py-0.5 rounded-full text-xs font-semibold`;

    el.querySelector('.incident-pattern').textContent     = inc.pattern || 'Unknown Pattern';
    el.querySelector('.incident-entity').textContent      = inc.entity  || '—';
    el.querySelector('.incident-stage').textContent       = inc.kill_chain_stage || '—';
    el.querySelector('.incident-events').textContent      = inc.event_count || inc.events?.length || '—';
    el.querySelector('.incident-score').textContent       = score;
    el.querySelector('.incident-technique-id').textContent   = mitre.technique_id   || 'N/A';
    el.querySelector('.incident-technique-name').textContent = mitre.technique_name  || '—';
    el.querySelector('.incident-tactic').textContent         = mitre.tactic          || '—';
    el.querySelector('.incident-description').textContent    = mitre.description     || '';

    list.appendChild(card);
  }
}

function renderMitreCoverage(incidents) {
  const container = document.getElementById('mitre-coverage');
  const seen = new Set();
  const chips = [];

  for (const inc of (incidents || [])) {
    const m = inc.mitre || {};
    const id = m.technique_id;
    if (id && id !== 'UNKNOWN' && !seen.has(id)) {
      seen.add(id);
      chips.push({ id, name: m.technique_name || '', tactic: m.tactic || '' });
    }
  }

  if (!chips.length) {
    container.innerHTML = '<span class="text-xs text-muted">No MITRE techniques mapped yet</span>';
    return;
  }

  container.innerHTML = chips.map(c => `
    <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-border text-xs font-mono
                 border border-medium/20 text-medium hover:border-medium/60 transition-colors cursor-default"
          title="${c.tactic}">
      ${c.id}
      <span class="text-muted font-sans">${c.name}</span>
    </span>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  loadPageData();
  setInterval(loadPageData, 20000);
});
