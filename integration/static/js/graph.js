/* ── Attack Graph page JS — NetWatch SIH26153 ────────────── */

async function loadPageData() {
  try {
    const res  = await fetch('/api/graph');
    const data = await res.json();
    renderGraph(data);

    const nodes    = data.nodes || [];
    const edges    = data.edges || [];
    const attackers = nodes.filter(n => n.type === 'attacker').length;

    document.getElementById('g-node-count').textContent    = nodes.length;
    document.getElementById('g-edge-count').textContent    = edges.length;
    document.getElementById('g-attacker-count').textContent = attackers;
  } catch (err) {
    console.error('Graph load failed:', err);
    document.getElementById('attack-graph').innerHTML =
      '<p class="text-muted text-center pt-32">Could not load graph data — run the pipeline first.</p>';
  }
}

function renderGraph(data) {
  const el    = document.getElementById('attack-graph');
  const nodes = data.nodes || [];
  const edges = data.edges || [];

  if (!nodes.length) {
    el.innerHTML = '<p class="text-muted text-center pt-32">No attack graph data yet — run the pipeline first.</p>';
    return;
  }

  // --- Spring layout: assign x/y positions via simple force simulation ---
  const pos = {};
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    pos[n.id] = { x: Math.cos(angle) * 2, y: Math.sin(angle) * 2 };
  });

  // Slightly push attackers outward, targets inward
  nodes.forEach(n => {
    if (n.type === 'attacker') {
      pos[n.id].x *= 1.5;
      pos[n.id].y *= 1.5;
    }
  });

  // Build Plotly traces
  const edgeX = [], edgeY = [], edgeColor = [];
  const annots = [];

  for (const e of edges) {
    const src = pos[e.from];
    const dst = pos[e.to];
    if (!src || !dst) continue;
    edgeX.push(src.x, dst.x, null);
    edgeY.push(src.y, dst.y, null);

    // Mid-point label annotation
    annots.push({
      x:         (src.x + dst.x) / 2,
      y:         (src.y + dst.y) / 2,
      text:      `<span style="font-size:9px;color:${e.color || '#8b949e'}">${e.label || ''}</span>`,
      showarrow: false,
      font:      { size: 9 },
    });
  }

  const edgeTrace = {
    x: edgeX, y: edgeY,
    mode: 'lines',
    line: { width: 1.5, color: '#30363d' },
    hoverinfo: 'none',
    type: 'scatter',
  };

  const nodeColors = nodes.map(n =>
    n.type === 'attacker' ? '#f85149' : '#58a6ff'
  );
  const nodeSymbols = nodes.map(n =>
    n.type === 'attacker' ? 'diamond' : 'circle'
  );

  const nodeTrace = {
    x: nodes.map(n => pos[n.id].x),
    y: nodes.map(n => pos[n.id].y),
    mode: 'markers+text',
    type: 'scatter',
    marker: {
      size:   nodes.map(n => n.type === 'attacker' ? 14 : 11),
      color:  nodeColors,
      symbol: nodeSymbols,
      line:   { width: 1.5, color: '#21262d' },
    },
    text:      nodes.map(n => n.label),
    textfont:  { size: 9, color: '#8b949e' },
    textposition: 'top center',
    hovertemplate: '%{text}<extra></extra>',
    customdata: nodes.map(n => n.type),
  };

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor:  'transparent',
    margin:  { t: 10, r: 10, b: 10, l: 10 },
    xaxis:   { showgrid: false, zeroline: false, showticklabels: false },
    yaxis:   { showgrid: false, zeroline: false, showticklabels: false },
    showlegend:  false,
    annotations: annots,
    dragmode:    'pan',
  };

  Plotly.newPlot(el, [edgeTrace, nodeTrace], layout, {
    responsive:      true,
    displayModeBar:  false,
    scrollZoom:      true,
  });
}

document.addEventListener('DOMContentLoaded', () => {
  loadPageData();
  setInterval(loadPageData, 30000);
});
