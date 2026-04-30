// dashboard.js
// Main dashboard logic. Loads JSON data, maintains a unified filter state,
// and renders KPIs, sparklines, risk heatmap, top concerns, charts, table,
// ECU breakdown, and (via compliance.js) the compliance matrix.

import { renderCompliance } from "./compliance.js";

const SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"];
const SEV_COLORS = {
  CRITICAL: "#ff4d4d",
  HIGH:     "#ff8c42",
  MEDIUM:   "#f5c542",
  LOW:      "#3fb950",
  UNKNOWN:  "#8b949e",
  NONE:     "#8b949e",
};

const state = {
  cves: [],
  ecuMap: {},
  complianceMap: {},
  filters: {
    oem: "all",
    severity: null,
    ecuClass: null,
    component: null,
    category: null,
    clause: null,    // { standard, clauseId }
    search: "",
  },
  sort: { key: "published", dir: "desc" },
  expanded: new Set(),
  charts: {},
};

init().catch(err => {
  console.error(err);
  const el = document.getElementById("last-updated");
  if (el) el.textContent = "Failed to load data";
  hideLoading();
});

async function init() {
  // Fetch health alongside data; health is non-blocking - if it 404s we still render.
  const [cveDoc, ecuMap, complianceMap, healthDoc] = await Promise.all([
    fetchJson("data/cves.json"),
    fetchJson("data/ecu_components.json"),
    fetchJson("data/compliance_map.json"),
    fetchJson("data/health.json").catch(() => null),
  ]);

  state.cves = cveDoc.cves || [];
  state.ecuMap = ecuMap;
  state.complianceMap = complianceMap;

  document.getElementById("last-updated").textContent =
    `Last refreshed: ${formatDate(cveDoc.generated_at)} · ${state.cves.length} CVEs`;

  renderHealthPill(healthDoc, cveDoc);
  wireHealthPopover();

  populateEcuFilter();
  wireOemFilter();
  wireTabs();
  wireCveFilters();
  wireKeyboard();
  wireClearFilters();
  wireTableSort();

  renderAll();
  hideLoading();
}

// ============== Health pill ==============
function renderHealthPill(health, cveDoc) {
  const pill = document.getElementById("health-pill");
  const label = document.getElementById("health-label");
  if (!pill || !label) return;

  const key   = health?.key   || { status: "unknown", message: "" };
  const fetch = health?.fetch || { status: "never_run" };

  // Determine overall status
  let status = "unknown";
  let text   = "Status: unknown";

  if (key.status === "valid") {
    // Check staleness against cves.json generated_at (or health.checked_at)
    const stamp = cveDoc?.generated_at || health?.checked_at;
    const ageDays = stamp ? (Date.now() - new Date(stamp).getTime()) / 86400000 : null;
    if (fetch.status === "ok" && (ageDays === null || ageDays <= 2)) {
      status = "ok";   text = "API key OK";
    } else if (fetch.status === "ok" && ageDays > 2) {
      status = "warn"; text = `Data stale (${Math.floor(ageDays)}d)`;
    } else if (fetch.status === "failed") {
      status = "error"; text = "Last fetch failed";
    } else if (fetch.status === "skipped") {
      status = "warn"; text = "Fetch skipped";
    } else {
      status = "warn"; text = "Key OK · awaiting fetch";
    }
  } else if (key.status === "invalid") {
    status = "error"; text = "API key invalid";
  } else if (key.status === "missing") {
    status = "error"; text = "API key missing";
  } else if (key.status === "error") {
    status = "error"; text = "Health-check error";
  } else if (key.status === "unknown") {
    status = "unknown"; text = "Health-check pending";
  }

  pill.dataset.status = status;
  label.textContent = text;
  pill.dataset.health = JSON.stringify(health || {});
  pill.title = key.message || "";
}

function wireHealthPopover() {
  const pill = document.getElementById("health-pill");
  const pop  = document.getElementById("health-popover");
  if (!pill || !pop) return;

  pill.addEventListener("click", (e) => {
    e.stopPropagation();
    if (!pop.hidden) { pop.hidden = true; return; }
    const health = JSON.parse(pill.dataset.health || "{}");
    pop.innerHTML = renderHealthPopoverHtml(health);
    pop.hidden = false;
  });
  document.addEventListener("click", (e) => {
    if (!pop.hidden && !pop.contains(e.target) && e.target !== pill) {
      pop.hidden = true;
    }
  });
}

function renderHealthPopoverHtml(health) {
  const key = health.key || {};
  const fetch = health.fetch || {};
  const checked = health.checked_at ? formatDate(health.checked_at) : "never";

  const statusBadge = (s) => {
    const color = ({
      valid: "var(--low)", invalid: "var(--crit)", missing: "var(--crit)",
      error: "var(--crit)", ok: "var(--low)", failed: "var(--crit)",
      skipped: "var(--med)", never_run: "var(--muted)", unknown: "var(--muted)",
    })[s] || "var(--muted)";
    return `<span style="color:${color};font-weight:600;text-transform:uppercase;font-size:11px;">${escapeHtml(s || "unknown")}</span>`;
  };

  return `
    <h4>NVD API key</h4>
    <dl>
      <dt>Status</dt><dd>${statusBadge(key.status)}</dd>
      <dt>Last checked</dt><dd>${escapeHtml(checked)}</dd>
      <dt>HTTP</dt><dd>${escapeHtml(String(key.http_status ?? "—"))}</dd>
      <dt>Rate limit</dt><dd>${key.rate_limit ? `${key.rate_limit}/30s` : "—"}</dd>
      <dt>Message</dt><dd>${escapeHtml(key.message || "—")}</dd>
    </dl>
    <div class="hp-divider"></div>
    <h4>Last fetch</h4>
    <dl>
      <dt>Status</dt><dd>${statusBadge(fetch.status)}</dd>
      <dt>Ran at</dt><dd>${fetch.ran_at ? escapeHtml(formatDate(fetch.ran_at)) : "—"}</dd>
      <dt>CVEs written</dt><dd>${fetch.cve_count ?? "—"}</dd>
      <dt>Message</dt><dd>${escapeHtml(fetch.message || "—")}</dd>
    </dl>
    <div class="hp-divider"></div>
    <p style="margin:0;color:var(--muted-2);font-size:11px;">
      Updated by the <code>Refresh NVD data</code> GitHub Action on each run.
    </p>`;
}

function hideLoading() {
  const el = document.getElementById("loading-overlay");
  if (el) {
    el.classList.add("hidden");
    setTimeout(() => el.remove(), 300);
  }
}

async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${path}: ${res.status}`);
  return res.json();
}

function formatDate(iso) {
  if (!iso) return "n/a";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

// ============== Wiring ==============
function populateEcuFilter() {
  const select = document.getElementById("filter-ecu");
  const seen = new Set();
  for (const oem of Object.values(state.ecuMap)) {
    for (const [id, cls] of Object.entries(oem.ecu_classes || {})) {
      if (!seen.has(id)) {
        seen.add(id);
        const opt = document.createElement("option");
        opt.value = id;
        opt.textContent = cls.label || id;
        select.appendChild(opt);
      }
    }
  }
}

function wireOemFilter() {
  document.getElementById("oem-filter").addEventListener("click", (e) => {
    const btn = e.target.closest("button.chip");
    if (!btn) return;
    document.querySelectorAll("#oem-filter .chip").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    state.filters.oem = btn.dataset.oem;
    renderAll();
  });
}

function wireTabs() {
  document.getElementById("tabs").addEventListener("click", (e) => {
    const btn = e.target.closest("button.tab");
    if (!btn) return;
    document.querySelectorAll("#tabs .tab").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    document.getElementById(`panel-${tab}`).classList.add("active");
    if (tab === "overview") renderCharts();
  });
}

function wireCveFilters() {
  document.getElementById("cve-search").addEventListener("input", (e) => {
    state.filters.search = e.target.value.trim().toLowerCase();
    renderTable();
    renderActiveFilters();
  });
  document.getElementById("filter-severity").addEventListener("change", (e) => {
    state.filters.severity = e.target.value === "all" ? null : e.target.value;
    renderTable();
    renderActiveFilters();
  });
  document.getElementById("filter-ecu").addEventListener("change", (e) => {
    state.filters.ecuClass = e.target.value === "all" ? null : e.target.value;
    renderTable();
    renderActiveFilters();
  });
  document.getElementById("cve-empty-clear").addEventListener("click", clearAllFilters);
}

function wireKeyboard() {
  window.addEventListener("keydown", (e) => {
    if (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName)) {
      e.preventDefault();
      // Switch to CVE tab if not active
      const cveTab = document.querySelector('[data-tab="cves"]');
      if (cveTab && !cveTab.classList.contains("active")) cveTab.click();
      document.getElementById("cve-search").focus();
    }
    if (e.key === "Escape") clearAllFilters();
  });
}

function wireClearFilters() {
  document.getElementById("clear-filters").addEventListener("click", clearAllFilters);
}

function wireTableSort() {
  document.querySelectorAll("#cve-table th[data-sort]").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) {
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort.key = key;
        state.sort.dir = "desc";
      }
      renderTable();
    });
  });
}

function clearAllFilters() {
  state.filters.severity = null;
  state.filters.ecuClass = null;
  state.filters.component = null;
  state.filters.category = null;
  state.filters.clause = null;
  state.filters.search = "";
  document.getElementById("cve-search").value = "";
  document.getElementById("filter-severity").value = "all";
  document.getElementById("filter-ecu").value = "all";
  renderAll();
}

// ============== Filtering ==============
function filterByOem(cves) {
  if (state.filters.oem === "all") return cves;
  return cves.filter(c => (c.matched_oems || []).includes(state.filters.oem));
}

function filterAll(cves) {
  // Apply ALL filters (used by table and most renders)
  return cves.filter(c => {
    const f = state.filters;
    if (f.severity && (c.severity || "").toUpperCase() !== f.severity) return false;
    if (f.ecuClass && c.ecu_class !== f.ecuClass) return false;
    if (f.component && !(c.components || []).includes(f.component)) return false;
    if (f.category && !(c.categories || []).includes(f.category)) return false;
    if (f.clause) {
      const cveCats = c.categories || [];
      const matched = cveCats.some(catId => {
        const cat = state.complianceMap.categories.find(x => x.id === catId);
        if (!cat) return false;
        const list = (cat.clauses || {})[f.clause.standard] || [];
        return list.includes(f.clause.clauseId);
      });
      if (!matched) return false;
    }
    if (f.search) {
      const hay = [
        c.id,
        c.description,
        ...(c.components || []),
        ...(c.matched_keywords || []),
      ].join(" ").toLowerCase();
      if (!hay.includes(f.search)) return false;
    }
    return true;
  });
}

// Returns the OEM-scoped cves and the fully-filtered subset.
function getFilteredSets() {
  const oemCves = filterByOem(state.cves);
  const filtered = filterAll(oemCves);
  return { oemCves, filtered };
}

// ============== Render orchestration ==============
function renderAll() {
  renderActiveFilters();
  const { oemCves, filtered } = getFilteredSets();
  renderKpis(filtered, oemCves);
  renderHeatmap(oemCves);
  renderTopConcerns(filtered);
  renderCharts(filtered);
  renderTable();
  renderEcuBreakdown(oemCves);
  renderCompliance(filtered, state.complianceMap, document.getElementById("compliance-content"), {
    onClauseClick: (standardId, clauseId) => {
      state.filters.clause = { standard: standardId, clauseId };
      // Switch to CVE tab to show the result
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    },
    activeClause: state.filters.clause,
  });
}

// ============== Active filter chips ==============
function renderActiveFilters() {
  const chipsEl = document.getElementById("active-filter-chips");
  const wrap = document.getElementById("active-filters");
  const f = state.filters;

  const chips = [];
  if (f.severity) chips.push({ key: "severity", label: `Severity: ${f.severity}` });
  if (f.ecuClass) chips.push({ key: "ecuClass", label: `ECU: ${displayEcu(f.ecuClass)}` });
  if (f.component) chips.push({ key: "component", label: `Component: ${f.component}` });
  if (f.category) {
    const cat = state.complianceMap.categories.find(c => c.id === f.category);
    chips.push({ key: "category", label: `Category: ${cat?.label || f.category}` });
  }
  if (f.clause) chips.push({ key: "clause", label: `Clause: ${f.clause.standard} ${f.clause.clauseId}` });
  if (f.search) chips.push({ key: "search", label: `Search: "${f.search}"` });

  if (chips.length === 0) {
    wrap.hidden = true;
    chipsEl.innerHTML = "";
    return;
  }
  wrap.hidden = false;
  chipsEl.innerHTML = chips.map(c =>
    `<span class="filter-chip">${escapeHtml(c.label)}<button data-key="${c.key}" aria-label="Remove">×</button></span>`
  ).join("");
  chipsEl.querySelectorAll("button").forEach(b => {
    b.addEventListener("click", () => {
      const k = b.dataset.key;
      if (k === "search") {
        state.filters.search = "";
        document.getElementById("cve-search").value = "";
      } else if (k === "severity") {
        state.filters.severity = null;
        document.getElementById("filter-severity").value = "all";
      } else if (k === "ecuClass") {
        state.filters.ecuClass = null;
        document.getElementById("filter-ecu").value = "all";
      } else {
        state.filters[k] = null;
      }
      renderAll();
    });
  });
}

// ============== KPIs + sparklines ==============
function renderKpis(filtered, oemCves) {
  const total = filtered.length;
  const crit  = filtered.filter(c => c.severity === "CRITICAL").length;
  const high  = filtered.filter(c => c.severity === "HIGH").length;
  const scored = filtered.filter(c => typeof c.cvss === "number");
  const avg = scored.length ? (scored.reduce((s, c) => s + c.cvss, 0) / scored.length).toFixed(1) : "—";

  document.getElementById("kpi-total").textContent    = total;
  document.getElementById("kpi-critical").textContent = crit;
  document.getElementById("kpi-high").textContent     = high;
  document.getElementById("kpi-avg").textContent      = avg;

  // Trend hint for avg CVSS: compare last 90 days vs prior 90
  const now = new Date();
  const threshold = new Date(now.getTime() - 90*86400000);
  const recent = filtered.filter(c => new Date(c.published) >= threshold && typeof c.cvss === "number");
  const older  = filtered.filter(c => new Date(c.published) <  threshold && typeof c.cvss === "number");
  const recentAvg = recent.length ? recent.reduce((s,c)=>s+c.cvss,0)/recent.length : null;
  const olderAvg  = older.length  ? older.reduce((s,c)=>s+c.cvss,0)/older.length   : null;
  const trendEl = document.getElementById("kpi-avg-trend");
  if (recentAvg !== null && olderAvg !== null) {
    const diff = (recentAvg - olderAvg).toFixed(1);
    const arrow = diff > 0 ? "↑" : diff < 0 ? "↓" : "→";
    trendEl.textContent = `90-day vs prior: ${arrow} ${Math.abs(diff)}`;
    trendEl.style.color = diff > 0.2 ? "var(--high)" : diff < -0.2 ? "var(--low)" : "var(--muted)";
  } else {
    trendEl.textContent = "";
  }

  // Sparklines: monthly counts for total / critical / high
  drawSparkline("spark-total",    monthlyCounts(filtered),                                      "#58a6ff");
  drawSparkline("spark-critical", monthlyCounts(filtered.filter(c=>c.severity==="CRITICAL")),   "#ff4d4d");
  drawSparkline("spark-high",     monthlyCounts(filtered.filter(c=>c.severity==="HIGH")),       "#ff8c42");
}

function monthlyCounts(cves) {
  const by = {};
  for (const c of cves) {
    const ym = (c.published || "").slice(0, 7);
    if (!ym) continue;
    by[ym] = (by[ym] || 0) + 1;
  }
  const months = Object.keys(by).sort();
  return months.map(m => by[m]);
}

function drawSparkline(canvasId, data, color) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const cfg = {
    type: "line",
    data: {
      labels: data.map((_, i) => i),
      datasets: [{
        data,
        borderColor: color,
        backgroundColor: hexToRgba(color, 0.18),
        borderWidth: 1.5,
        pointRadius: 0,
        fill: true,
        tension: 0.35,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
      animation: false,
    },
  };
  if (state.charts[canvasId]) {
    state.charts[canvasId].data = cfg.data;
    state.charts[canvasId].update("none");
  } else {
    state.charts[canvasId] = new Chart(ctx, cfg);
  }
}

function hexToRgba(hex, a) {
  const h = hex.replace("#","");
  const bigint = parseInt(h, 16);
  const r = (bigint >> 16) & 255, g = (bigint >> 8) & 255, b = bigint & 255;
  return `rgba(${r},${g},${b},${a})`;
}

// ============== Heatmap ==============
function renderHeatmap(oemCves) {
  const container = document.getElementById("heatmap");
  const oemIds = state.filters.oem === "all"
    ? Object.keys(state.ecuMap)
    : [state.filters.oem];

  // Build column set = union of ECU class IDs across visible OEMs
  const ecuClassIds = [];
  for (const oemId of oemIds) {
    for (const id of Object.keys(state.ecuMap[oemId]?.ecu_classes || {})) {
      if (!ecuClassIds.includes(id)) ecuClassIds.push(id);
    }
  }

  // Compute counts and max severity per cell
  const cells = {};
  for (const oemId of oemIds) {
    for (const ecuId of ecuClassIds) {
      cells[`${oemId}|${ecuId}`] = { count: 0, maxCvss: 0, maxSev: "NONE" };
    }
  }
  for (const c of oemCves) {
    if (!c.ecu_class) continue;
    for (const oemId of (c.matched_oems || [])) {
      if (!oemIds.includes(oemId)) continue;
      const k = `${oemId}|${c.ecu_class}`;
      if (!cells[k]) continue;
      cells[k].count += 1;
      const score = typeof c.cvss === "number" ? c.cvss : 0;
      if (score > cells[k].maxCvss) {
        cells[k].maxCvss = score;
        cells[k].maxSev = c.severity || cells[k].maxSev;
      }
    }
  }

  const cols = ecuClassIds.length + 1;
  let html = `<div class="heatmap-grid" style="grid-template-columns: 160px repeat(${ecuClassIds.length}, minmax(110px, 1fr));">`;
  // Header row
  html += `<div class="heat-header">OEM &darr; / ECU &rarr;</div>`;
  for (const ecuId of ecuClassIds) {
    const label = displayEcu(ecuId);
    html += `<div class="heat-header">${escapeHtml(label)}</div>`;
  }
  // Body rows
  for (const oemId of oemIds) {
    html += `<div class="heat-row-label">${escapeHtml(state.ecuMap[oemId]?.display_name || oemId)}</div>`;
    for (const ecuId of ecuClassIds) {
      const cell = cells[`${oemId}|${ecuId}`];
      if (!cell || cell.count === 0) {
        html += `<div class="heat-cell empty"><span class="hc-count">0</span></div>`;
      } else {
        const lvl = cell.maxSev.toLowerCase();
        html += `
          <div class="heat-cell lvl-${lvl}" data-oem="${oemId}" data-ecu="${ecuId}" title="${cell.count} CVE(s), max CVSS ${cell.maxCvss.toFixed(1)}">
            <span class="hc-count">${cell.count}</span>
            <span class="hc-meta">max ${cell.maxCvss.toFixed(1)}</span>
          </div>`;
      }
    }
  }
  html += `</div>`;
  container.innerHTML = html;

  container.querySelectorAll(".heat-cell:not(.empty)").forEach(cell => {
    cell.addEventListener("click", () => {
      const oemId = cell.dataset.oem;
      const ecuId = cell.dataset.ecu;
      // Set OEM chip + ECU filter
      document.querySelectorAll("#oem-filter .chip").forEach(c => {
        c.classList.toggle("active", c.dataset.oem === oemId);
      });
      state.filters.oem = oemId;
      state.filters.ecuClass = ecuId;
      document.getElementById("filter-ecu").value = ecuId;
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    });
  });
}

// ============== Top concerns ==============
function renderTopConcerns(filtered) {
  const mount = document.getElementById("top-concerns");
  if (!filtered.length) {
    mount.innerHTML = `<p class="card-hint" style="padding:8px;">No CVEs in current filter set.</p>`;
    return;
  }
  const now = Date.now();
  const ranked = filtered
    .map(c => {
      const cvss = typeof c.cvss === "number" ? c.cvss : 0;
      const recencyDays = c.published ? Math.max(0, (now - new Date(c.published).getTime()) / 86400000) : 9999;
      const recencyBoost = recencyDays < 90 ? (90 - recencyDays) / 90 * 3 : 0;
      const oemBoost = (c.matched_oems || []).length * 0.5;
      return { cve: c, score: cvss + recencyBoost + oemBoost };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  mount.innerHTML = ranked.map((r, i) => {
    const c = r.cve;
    const oems = (c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("");
    return `
      <div class="concern-item" data-cve="${escapeAttr(c.id)}">
        <div class="concern-rank">${i+1}</div>
        <div class="concern-body">
          <div class="concern-title">
            <a href="${escapeAttr(c.url)}" target="_blank" rel="noreferrer" onclick="event.stopPropagation()">${escapeHtml(c.id)}</a>
            <span class="sev-badge sev-${escapeAttr(c.severity || "UNKNOWN")}">${escapeHtml(c.severity || "?")}</span>
            ${oems}
          </div>
          <div class="concern-meta">${escapeHtml(truncate(c.description || "", 140))}</div>
        </div>
        <div class="concern-score" style="color:${SEV_COLORS[c.severity] || "#8b949e"}">${(c.cvss ?? "—")}</div>
      </div>`;
  }).join("");

  mount.querySelectorAll(".concern-item").forEach(el => {
    el.addEventListener("click", () => {
      const cveId = el.dataset.cve;
      state.filters.search = cveId.toLowerCase();
      document.getElementById("cve-search").value = cveId;
      state.expanded.add(cveId);
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    });
  });
}

// ============== Charts ==============
function renderCharts(filteredArg) {
  const filtered = filteredArg || getFilteredSets().filtered;

  // Stacked severity trend (area)
  const monthSet = new Set();
  for (const c of filtered) {
    const ym = (c.published || "").slice(0, 7);
    if (ym) monthSet.add(ym);
  }
  const months = [...monthSet].sort();
  const sevSeries = {};
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    sevSeries[sev] = months.map(m =>
      filtered.filter(c => c.severity === sev && (c.published || "").slice(0,7) === m).length
    );
  }
  upsertChart("chart-trend", "line", {
    labels: months,
    datasets: ["LOW","MEDIUM","HIGH","CRITICAL"].map(sev => ({
      label: sev,
      data: sevSeries[sev],
      borderColor: SEV_COLORS[sev],
      backgroundColor: hexToRgba(SEV_COLORS[sev], 0.4),
      fill: true,
      tension: 0.3,
      pointRadius: 0,
    })),
  }, {
    scales: {
      x: { stacked: true, ticks: { color: "#8b949e" }, grid: { color: "#2a313c" } },
      y: { stacked: true, ticks: { color: "#8b949e" }, grid: { color: "#2a313c" }, beginAtZero: true, precision: 0 },
    },
    plugins: { legend: { position: "bottom", labels: { color: "#e6edf3", boxWidth: 12 } } },
  });

  // Top components horizontal bar (click to filter)
  const compCounts = {};
  for (const c of filtered) {
    for (const comp of (c.components || [])) {
      compCounts[comp] = (compCounts[comp] || 0) + 1;
    }
  }
  const top = Object.entries(compCounts).sort((a,b) => b[1]-a[1]).slice(0, 10);
  upsertChart("chart-components", "bar", {
    labels: top.map(t => t[0]),
    datasets: [{
      label: "CVEs",
      data: top.map(t => t[1]),
      backgroundColor: "#1f6feb",
      hoverBackgroundColor: "#58a6ff",
      borderRadius: 4,
    }],
  }, {
    indexAxis: "y",
    onClick: (evt, els) => {
      if (!els.length) return;
      const label = top[els[0].index][0];
      state.filters.component = label;
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    },
    scales: {
      x: { ticks: { color: "#8b949e" }, grid: { color: "#2a313c" }, beginAtZero: true, precision: 0 },
      y: { ticks: { color: "#e6edf3" }, grid: { color: "#2a313c" } },
    },
    plugins: { legend: { display: false } },
  });

  // OEM comparison stacked bar
  const oemIds = Object.keys(state.ecuMap);
  const compareDatasets = ["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => ({
    label: sev,
    backgroundColor: SEV_COLORS[sev],
    data: oemIds.map(o => filtered.filter(c =>
      (c.matched_oems || []).includes(o) && c.severity === sev
    ).length),
    borderRadius: 4,
  }));
  upsertChart("chart-oem-compare", "bar", {
    labels: oemIds.map(o => state.ecuMap[o]?.display_name || o),
    datasets: compareDatasets,
  }, {
    onClick: (evt, els) => {
      if (!els.length) return;
      const oemId = oemIds[els[0].index];
      const sev   = compareDatasets[els[0].datasetIndex].label;
      document.querySelectorAll("#oem-filter .chip").forEach(c => {
        c.classList.toggle("active", c.dataset.oem === oemId);
      });
      state.filters.oem = oemId;
      state.filters.severity = sev;
      document.getElementById("filter-severity").value = sev;
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    },
    scales: {
      x: { stacked: true, ticks: { color: "#e6edf3" }, grid: { color: "#2a313c" } },
      y: { stacked: true, ticks: { color: "#8b949e" }, grid: { color: "#2a313c" }, beginAtZero: true, precision: 0 },
    },
    plugins: { legend: { position: "bottom", labels: { color: "#e6edf3", boxWidth: 12 } } },
  });
}

function upsertChart(canvasId, type, data, options = {}) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "#e6edf3" } } },
  };
  const merged = mergeOptions(baseOptions, options);
  if (state.charts[canvasId]) {
    state.charts[canvasId].config.type = type;
    state.charts[canvasId].data = data;
    state.charts[canvasId].options = merged;
    state.charts[canvasId].update();
    return;
  }
  state.charts[canvasId] = new Chart(ctx, { type, data, options: merged });
}

function mergeOptions(a, b) {
  return {
    ...a, ...b,
    plugins: { ...(a.plugins||{}), ...(b.plugins||{}) },
    scales:  { ...(a.scales||{}),  ...(b.scales||{}) },
  };
}

// ============== CVE table ==============
function renderTable() {
  const { oemCves, filtered } = getFilteredSets();
  const sorted = sortCves(filtered);
  const tbody = document.getElementById("cve-tbody");
  const emptyEl = document.getElementById("cve-empty");

  document.getElementById("cve-count").textContent = `${sorted.length} of ${oemCves.length} match`;

  // Update sort indicators on headers
  document.querySelectorAll("#cve-table th[data-sort]").forEach(th => {
    th.classList.remove("sort-asc","sort-desc");
    if (th.dataset.sort === state.sort.key) {
      th.classList.add(state.sort.dir === "asc" ? "sort-asc" : "sort-desc");
    }
  });

  if (!sorted.length) {
    tbody.innerHTML = "";
    emptyEl.hidden = false;
    return;
  }
  emptyEl.hidden = true;

  tbody.innerHTML = sorted.map(c => {
    const isOpen = state.expanded.has(c.id);
    const detailRow = isOpen ? `
      <tr class="detail" data-cve="${escapeAttr(c.id)}-detail">
        <td colspan="9">
          <div class="detail-grid">
            <div>
              <h5>Full description</h5>
              <p>${escapeHtml(c.description || "")}</p>
            </div>
            <div>
              <h5>All matched OEMs</h5>
              <p>${(c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>All components</h5>
              <p>${(c.components || []).map(x => `<span class="tag click" data-comp="${escapeAttr(x)}">${escapeHtml(x)}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>Matched keywords</h5>
              <p>${(c.matched_keywords || []).map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>Compliance clauses touched</h5>
              <p>${describeClauses(c)}</p>
            </div>
            <div>
              <h5>Source</h5>
              <p><a href="${escapeAttr(c.url)}" target="_blank" rel="noreferrer">${escapeHtml(c.url || "")}</a></p>
            </div>
          </div>
        </td>
      </tr>` : "";

    return `
      <tr class="row ${isOpen ? "expanded" : ""}" data-cve="${escapeAttr(c.id)}">
        <td><span class="expand-toggle">▶</span></td>
        <td><a href="${escapeAttr(c.url)}" target="_blank" rel="noreferrer" onclick="event.stopPropagation()">${escapeHtml(c.id)}</a></td>
        <td><span class="sev-badge sev-${escapeAttr(c.severity || "UNKNOWN")}">${escapeHtml(c.severity || "?")}</span></td>
        <td>${c.cvss ?? "—"}</td>
        <td>${escapeHtml(c.published || "")}</td>
        <td>${(c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("")}</td>
        <td>${escapeHtml(displayEcu(c.ecu_class))}</td>
        <td>${(c.components || []).slice(0,4).map(x => `<span class="tag click" data-comp="${escapeAttr(x)}">${escapeHtml(x)}</span>`).join("")}${(c.components||[]).length>4 ? `<span class="tag">+${(c.components||[]).length-4}</span>`:``}</td>
        <td class="desc">${escapeHtml(truncate(c.description || "", 200))}</td>
      </tr>
      ${detailRow}`;
  }).join("");

  // Row click expands
  tbody.querySelectorAll("tr.row").forEach(tr => {
    tr.addEventListener("click", (e) => {
      // Avoid toggling when clicking a link or component tag
      if (e.target.closest("a")) return;
      if (e.target.closest(".tag.click")) return;
      const id = tr.dataset.cve;
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      renderTable();
    });
  });

  // Component tag click filters
  tbody.querySelectorAll(".tag.click").forEach(t => {
    t.addEventListener("click", (e) => {
      e.stopPropagation();
      state.filters.component = t.dataset.comp;
      renderAll();
    });
  });
}

function sortCves(cves) {
  const { key, dir } = state.sort;
  const mul = dir === "asc" ? 1 : -1;
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0, NONE: 0 };
  return [...cves].sort((a, b) => {
    let va, vb;
    if (key === "severity") { va = sevRank[a.severity] ?? 0; vb = sevRank[b.severity] ?? 0; }
    else if (key === "cvss")  { va = a.cvss ?? -1; vb = b.cvss ?? -1; }
    else                       { va = (a[key] || ""); vb = (b[key] || ""); }
    if (va < vb) return -1 * mul;
    if (va > vb) return  1 * mul;
    return 0;
  });
}

function describeClauses(cve) {
  const cats = cve.categories || [];
  if (!cats.length) return "—";
  const lines = [];
  for (const catId of cats) {
    const cat = state.complianceMap.categories.find(c => c.id === catId);
    if (!cat) continue;
    for (const [stdId, list] of Object.entries(cat.clauses || {})) {
      const stdName = state.complianceMap.standards[stdId]?.name || stdId;
      if (list.length) lines.push(`<span class="tag">${escapeHtml(stdName)}: ${escapeHtml(list.join(", "))}</span>`);
    }
  }
  return lines.join("") || "—";
}

// ============== ECU breakdown ==============
function renderEcuBreakdown(oemCvesArg) {
  const mount = document.getElementById("ecu-breakdown");
  const oemIds = state.filters.oem === "all"
    ? Object.keys(state.ecuMap)
    : [state.filters.oem];

  let html = "";
  for (const oemId of oemIds) {
    const oem = state.ecuMap[oemId];
    if (!oem) continue;
    const oemCves = oemCvesArg.filter(c => (c.matched_oems || []).includes(oemId));
    html += `<div class="oem-block">`;
    html += `<h2>${escapeHtml(oem.display_name)} <span class="tag">${oemCves.length} CVEs</span></h2>`;
    html += `<div class="ecu-grid">`;
    for (const [classId, cls] of Object.entries(oem.ecu_classes || {})) {
      const inClass = oemCves.filter(c => c.ecu_class === classId);
      const n = inClass.length;
      const dots = severityDots(inClass);
      html += `<div class="ecu-card" data-oem="${escapeAttr(oemId)}" data-ecu="${escapeAttr(classId)}">
        <h4>${escapeHtml(cls.label)}</h4>
        <div class="count">${n}</div>
        <div class="severity-dots">${dots}</div>
        <div class="components">${(cls.components || []).map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("")}</div>
      </div>`;
    }
    html += `</div></div>`;
  }
  mount.innerHTML = html;

  mount.querySelectorAll(".ecu-card").forEach(card => {
    card.addEventListener("click", () => {
      const oemId = card.dataset.oem;
      const ecuId = card.dataset.ecu;
      document.querySelectorAll("#oem-filter .chip").forEach(c => {
        c.classList.toggle("active", c.dataset.oem === oemId);
      });
      state.filters.oem = oemId;
      state.filters.ecuClass = ecuId;
      document.getElementById("filter-ecu").value = ecuId;
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    });
  });
}

function severityDots(cves) {
  // Render up to 5 dots colored by severity, most-severe first
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  for (const c of cves) if (counts[c.severity] !== undefined) counts[c.severity]++;
  const list = [];
  for (const sev of ["CRITICAL","HIGH","MEDIUM","LOW"]) {
    for (let i = 0; i < counts[sev] && list.length < 5; i++) list.push(sev);
  }
  while (list.length < 5) list.push("empty");
  return list.map(s => `<span class="d d-${s}">●</span>`).join("");
}

// ============== Helpers ==============
function displayOem(id) {
  return state.ecuMap[id]?.display_name || id;
}
function displayEcu(id) {
  if (!id) return "—";
  for (const oem of Object.values(state.ecuMap)) {
    if (oem.ecu_classes && oem.ecu_classes[id]) return oem.ecu_classes[id].label || id;
  }
  return id;
}
function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function escapeAttr(s) {
  return escapeHtml(s);
}
