// dashboard.js
import { renderCompliance } from "./compliance.js";

const SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"];
const SEV_COLORS = {
  CRITICAL: "#e53935",
  HIGH:     "#f4511e",
  MEDIUM:   "#f5a623",
  LOW:      "#43a868",
  UNKNOWN:  "#555555",
  NONE:     "#555555",
};

const CHART_GRID  = "rgba(255,255,255,0.05)";
const CHART_TEXT  = "#ebebeb";
const CHART_MUTED = "#777777";

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
    clause: null,
    search: "",
  },
  sort: { key: "published", dir: "desc" },
  expanded: new Set(),
  charts: {},
};

init().catch(err => {
  console.error(err);
  const el = document.getElementById("last-updated");
  if (el) el.textContent = "FAILED TO LOAD DATA";
  hideLoading();
});

async function init() {
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
    `REFRESHED: ${formatDate(cveDoc.generated_at)} · ${state.cves.length} CVEs`;

  renderHealthPill(healthDoc, cveDoc);
  wireHealthPopover();
  populateEcuFilter();
  wireOemFilter();
  wireTabs();
  wireCveFilters();
  wireKeyboard();
  wireClearFilters();
  wireTableSort();
  wireExport();
  renderResources();

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

  let status = "unknown";
  let text   = "STATUS: UNKNOWN";

  if (key.status === "valid") {
    const stamp = cveDoc?.generated_at || health?.checked_at;
    const ageDays = stamp ? (Date.now() - new Date(stamp).getTime()) / 86400000 : null;
    if (fetch.status === "ok" && (ageDays === null || ageDays <= 2)) {
      status = "ok";   text = "API KEY OK";
    } else if (fetch.status === "ok" && ageDays > 2) {
      status = "warn"; text = `DATA STALE (${Math.floor(ageDays)}D)`;
    } else if (fetch.status === "failed") {
      status = "error"; text = "LAST FETCH FAILED";
    } else if (fetch.status === "skipped") {
      status = "warn"; text = "FETCH SKIPPED";
    } else {
      status = "warn"; text = "KEY OK · AWAITING FETCH";
    }
  } else if (key.status === "invalid") {
    status = "error"; text = "API KEY INVALID";
  } else if (key.status === "missing") {
    status = "error"; text = "API KEY MISSING";
  } else if (key.status === "error") {
    status = "error"; text = "HEALTH-CHECK ERROR";
  } else {
    status = "unknown"; text = "HEALTH-CHECK PENDING";
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
    return `<span style="color:${color};font-weight:700;text-transform:uppercase;font-size:10px;">${escapeHtml(s || "unknown")}</span>`;
  };

  return `
    <h4>NVD API Key</h4>
    <dl>
      <dt>Status</dt><dd>${statusBadge(key.status)}</dd>
      <dt>Last checked</dt><dd>${escapeHtml(checked)}</dd>
      <dt>HTTP</dt><dd>${escapeHtml(String(key.http_status ?? "—"))}</dd>
      <dt>Rate limit</dt><dd>${key.rate_limit ? `${key.rate_limit}/30s` : "—"}</dd>
      <dt>Message</dt><dd>${escapeHtml(key.message || "—")}</dd>
    </dl>
    <div class="hp-divider"></div>
    <h4>Last Fetch</h4>
    <dl>
      <dt>Status</dt><dd>${statusBadge(fetch.status)}</dd>
      <dt>Ran at</dt><dd>${fetch.ran_at ? escapeHtml(formatDate(fetch.ran_at)) : "—"}</dd>
      <dt>CVEs written</dt><dd>${fetch.cve_count ?? "—"}</dd>
      <dt>Message</dt><dd>${escapeHtml(fetch.message || "—")}</dd>
    </dl>
    <div class="hp-divider"></div>
    <p style="margin:0;color:var(--muted-2);font-size:10px;">
      Updated by the <code>Refresh NVD data</code> GitHub Action on each run.
    </p>`;
}

function hideLoading() {
  const el = document.getElementById("loading-overlay");
  if (el) {
    el.classList.add("hidden");
    setTimeout(() => el.remove(), 400);
  }
}

async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${path}: ${res.status}`);
  return res.json();
}

function formatDate(iso) {
  if (!iso) return "N/A";
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

function wireExport() {
  const btn = document.getElementById("btn-export");
  if (btn) btn.addEventListener("click", exportCsv);
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

// ============== CSV Export ==============
function exportCsv() {
  const { filtered } = getFilteredSets();
  const headers = ["CVE ID", "Severity", "CVSS", "Published", "Modified", "OEMs", "ECU Class", "Components", "Categories", "Description", "URL"];
  const rows = [
    headers,
    ...filtered.map(c => [
      c.id,
      c.severity || "",
      c.cvss ?? "",
      c.published || "",
      c.modified || "",
      (c.matched_oems || []).join("; "),
      displayEcu(c.ecu_class),
      (c.components || []).join("; "),
      (c.categories || []).join("; "),
      (c.description || "").replace(/"/g, '""'),
      c.url || "",
    ]),
  ];
  const csv = rows.map(r => r.map(cell => `"${String(cell)}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `automotive-cves-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============== Filtering ==============
function filterByOem(cves) {
  if (state.filters.oem === "all") return cves;
  return cves.filter(c => (c.matched_oems || []).includes(state.filters.oem));
}

function filterAll(cves) {
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
  renderThreatLevel(filtered);
  renderHeatmap(oemCves);
  renderTopConcerns(filtered);
  renderCharts(filtered);
  renderTable();
  renderEcuBreakdown(oemCves);
  renderCompliance(filtered, state.complianceMap, document.getElementById("compliance-content"), {
    onClauseClick: (standardId, clauseId) => {
      state.filters.clause = { standard: standardId, clauseId };
      document.querySelector('[data-tab="cves"]').click();
      renderAll();
    },
    activeClause: state.filters.clause,
  });
}

// ============== Threat level ==============
function renderThreatLevel(filtered) {
  const el = document.getElementById("tl-value");
  if (!el) return;
  const total = filtered.length;
  if (!total) { el.textContent = "—"; el.style.color = ""; return; }
  const critRatio = filtered.filter(c => c.severity === "CRITICAL").length / total;
  const highRatio  = filtered.filter(c => c.severity === "HIGH").length / total;

  let level, color;
  if (critRatio >= 0.25) {
    level = "CRITICAL"; color = "#ff2244";
  } else if (critRatio >= 0.12 || highRatio >= 0.4) {
    level = "HIGH"; color = "#ff8800";
  } else if (critRatio > 0 || highRatio >= 0.2) {
    level = "ELEVATED"; color = "#ffcc00";
  } else {
    level = "GUARDED"; color = "#00e676";
  }
  el.textContent = level;
  el.style.color = color;
  el.style.textShadow = `0 0 12px ${color}88`;
}

// ============== Active filter chips ==============
function renderActiveFilters() {
  const chipsEl = document.getElementById("active-filter-chips");
  const wrap = document.getElementById("active-filters");
  const f = state.filters;

  const chips = [];
  if (f.severity) chips.push({ key: "severity", label: `SEVERITY: ${f.severity}` });
  if (f.ecuClass) chips.push({ key: "ecuClass", label: `ECU: ${displayEcu(f.ecuClass)}` });
  if (f.component) chips.push({ key: "component", label: `COMPONENT: ${f.component}` });
  if (f.category) {
    const cat = state.complianceMap.categories.find(c => c.id === f.category);
    chips.push({ key: "category", label: `CATEGORY: ${cat?.label || f.category}` });
  }
  if (f.clause) chips.push({ key: "clause", label: `CLAUSE: ${f.clause.standard} ${f.clause.clauseId}` });
  if (f.search) chips.push({ key: "search", label: `SEARCH: "${f.search}"` });

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
  const avgNum = scored.length ? scored.reduce((s, c) => s + c.cvss, 0) / scored.length : null;
  const avg = avgNum !== null ? avgNum.toFixed(1) : "—";

  animateCounter("kpi-total", total);
  animateCounter("kpi-critical", crit);
  animateCounter("kpi-high", high);
  document.getElementById("kpi-avg").textContent = avg;

  const now = new Date();
  const threshold = new Date(now.getTime() - 90 * 86400000);
  const recent = filtered.filter(c => new Date(c.published) >= threshold && typeof c.cvss === "number");
  const older  = filtered.filter(c => new Date(c.published) < threshold && typeof c.cvss === "number");
  const recentAvg = recent.length ? recent.reduce((s, c) => s + c.cvss, 0) / recent.length : null;
  const olderAvg  = older.length  ? older.reduce((s, c) => s + c.cvss, 0) / older.length   : null;
  const trendEl = document.getElementById("kpi-avg-trend");
  if (recentAvg !== null && olderAvg !== null) {
    const diff = (recentAvg - olderAvg).toFixed(1);
    const arrow = diff > 0 ? "↑" : diff < 0 ? "↓" : "→";
    trendEl.textContent = `90D VS PRIOR: ${arrow} ${Math.abs(diff)}`;
    trendEl.style.color = diff > 0.2 ? "var(--high)" : diff < -0.2 ? "var(--low)" : "var(--muted)";
  } else {
    trendEl.textContent = "";
  }

  drawSparkline("spark-total",    monthlyCounts(filtered),                                     "#00c8ff");
  drawSparkline("spark-critical", monthlyCounts(filtered.filter(c => c.severity === "CRITICAL")), "#ff2244");
  drawSparkline("spark-high",     monthlyCounts(filtered.filter(c => c.severity === "HIGH")),    "#ff8800");
}

function animateCounter(elId, target) {
  const el = document.getElementById(elId);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const duration = 600;
  let startTime = null;
  const step = (ts) => {
    if (!startTime) startTime = ts;
    const progress = Math.min((ts - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
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
        backgroundColor: hexToRgba(color, 0.15),
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
  const h = hex.replace("#", "");
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

  const ecuClassIds = [];
  for (const oemId of oemIds) {
    for (const id of Object.keys(state.ecuMap[oemId]?.ecu_classes || {})) {
      if (!ecuClassIds.includes(id)) ecuClassIds.push(id);
    }
  }

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

  let html = `<div class="heatmap-grid" style="grid-template-columns: 160px repeat(${ecuClassIds.length}, minmax(110px, 1fr));">`;
  html += `<div class="heat-header">OEM ↓ / ECU →</div>`;
  for (const ecuId of ecuClassIds) {
    html += `<div class="heat-header">${escapeHtml(displayEcu(ecuId))}</div>`;
  }
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
            <span class="hc-meta">MAX ${cell.maxCvss.toFixed(1)}</span>
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
        <div class="concern-rank">${i + 1}</div>
        <div class="concern-body">
          <div class="concern-title">
            <a href="${escapeAttr(c.url)}" target="_blank" rel="noreferrer" onclick="event.stopPropagation()">${escapeHtml(c.id)}</a>
            <span class="sev-badge sev-${escapeAttr(c.severity || "UNKNOWN")}">${escapeHtml(c.severity || "?")}</span>
            ${oems}
          </div>
          <div class="concern-meta">${escapeHtml(truncate(c.description || "", 140))}</div>
        </div>
        <div class="concern-score" style="color:${SEV_COLORS[c.severity] || "#4a7a9b"}">${c.cvss ?? "—"}</div>
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

  const monthSet = new Set();
  for (const c of filtered) {
    const ym = (c.published || "").slice(0, 7);
    if (ym) monthSet.add(ym);
  }
  const months = [...monthSet].sort();
  const sevSeries = {};
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    sevSeries[sev] = months.map(m =>
      filtered.filter(c => c.severity === sev && (c.published || "").slice(0, 7) === m).length
    );
  }
  upsertChart("chart-trend", "line", {
    labels: months,
    datasets: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(sev => ({
      label: sev,
      data: sevSeries[sev],
      borderColor: SEV_COLORS[sev],
      backgroundColor: hexToRgba(SEV_COLORS[sev], 0.35),
      fill: true,
      tension: 0.3,
      pointRadius: 0,
      borderWidth: 1.5,
    })),
  }, {
    scales: {
      x: { stacked: true, ticks: { color: CHART_MUTED, font: { size: 10 } }, grid: { color: CHART_GRID } },
      y: { stacked: true, ticks: { color: CHART_MUTED, font: { size: 10 } }, grid: { color: CHART_GRID }, beginAtZero: true, precision: 0 },
    },
    plugins: { legend: { position: "bottom", labels: { color: CHART_TEXT, boxWidth: 10, font: { size: 10 } } } },
  });

  const compCounts = {};
  for (const c of filtered) {
    for (const comp of (c.components || [])) {
      compCounts[comp] = (compCounts[comp] || 0) + 1;
    }
  }
  const top = Object.entries(compCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  upsertChart("chart-components", "bar", {
    labels: top.map(t => t[0]),
    datasets: [{
      label: "CVEs",
      data: top.map(t => t[1]),
      backgroundColor: "rgba(232,137,12,0.25)",
      hoverBackgroundColor: "rgba(232,137,12,0.5)",
      borderColor: "rgba(232,137,12,0.6)",
      borderWidth: 1,
      borderRadius: 3,
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
      x: { ticks: { color: CHART_MUTED, font: { size: 10 } }, grid: { color: CHART_GRID }, beginAtZero: true, precision: 0 },
      y: { ticks: { color: CHART_TEXT, font: { size: 10 } }, grid: { color: CHART_GRID } },
    },
    plugins: { legend: { display: false } },
  });

  const oemIds = Object.keys(state.ecuMap);
  const compareDatasets = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => ({
    label: sev,
    backgroundColor: hexToRgba(SEV_COLORS[sev], 0.7),
    hoverBackgroundColor: SEV_COLORS[sev],
    borderColor: SEV_COLORS[sev],
    borderWidth: 1,
    data: oemIds.map(o => filtered.filter(c =>
      (c.matched_oems || []).includes(o) && c.severity === sev
    ).length),
    borderRadius: 3,
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
      x: { stacked: true, ticks: { color: CHART_TEXT, font: { size: 10 } }, grid: { color: CHART_GRID } },
      y: { stacked: true, ticks: { color: CHART_MUTED, font: { size: 10 } }, grid: { color: CHART_GRID }, beginAtZero: true, precision: 0 },
    },
    plugins: { legend: { position: "bottom", labels: { color: CHART_TEXT, boxWidth: 10, font: { size: 10 } } } },
  });
}

function upsertChart(canvasId, type, data, options = {}) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: CHART_TEXT } } },
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
    plugins: { ...(a.plugins || {}), ...(b.plugins || {}) },
    scales:  { ...(a.scales || {}),  ...(b.scales || {}) },
  };
}

// ============== CVE table ==============
function renderTable() {
  const { oemCves, filtered } = getFilteredSets();
  const sorted = sortCves(filtered);
  const tbody = document.getElementById("cve-tbody");
  const emptyEl = document.getElementById("cve-empty");

  document.getElementById("cve-count").textContent = `${sorted.length} of ${oemCves.length} match`;

  document.querySelectorAll("#cve-table th[data-sort]").forEach(th => {
    th.classList.remove("sort-asc", "sort-desc");
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
              <h5>Full Description</h5>
              <p>${escapeHtml(c.description || "")}</p>
            </div>
            <div>
              <h5>Matched OEMs</h5>
              <p>${(c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>All Components</h5>
              <p>${(c.components || []).map(x => `<span class="tag click" data-comp="${escapeAttr(x)}">${escapeHtml(x)}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>Matched Keywords</h5>
              <p>${(c.matched_keywords || []).map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("") || "—"}</p>
            </div>
            <div>
              <h5>Compliance Clauses</h5>
              <p>${describeClauses(c)}</p>
            </div>
            <div>
              <h5>NVD Source</h5>
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
        <td style="font-family:var(--font-mono)">${c.cvss ?? "—"}</td>
        <td style="font-family:var(--font-mono);font-size:11px">${escapeHtml(c.published || "")}</td>
        <td>${(c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("")}</td>
        <td>${escapeHtml(displayEcu(c.ecu_class))}</td>
        <td>${(c.components || []).slice(0, 4).map(x => `<span class="tag click" data-comp="${escapeAttr(x)}">${escapeHtml(x)}</span>`).join("")}${(c.components || []).length > 4 ? `<span class="tag">+${(c.components || []).length - 4}</span>` : ``}</td>
        <td class="desc">${escapeHtml(truncate(c.description || "", 200))}</td>
      </tr>
      ${detailRow}`;
  }).join("");

  tbody.querySelectorAll("tr.row").forEach(tr => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("a")) return;
      if (e.target.closest(".tag.click")) return;
      const id = tr.dataset.cve;
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      renderTable();
    });
  });

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
    else if (key === "cvss") { va = a.cvss ?? -1; vb = b.cvss ?? -1; }
    else                     { va = (a[key] || ""); vb = (b[key] || ""); }
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
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const c of cves) if (counts[c.severity] !== undefined) counts[c.severity]++;
  const list = [];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    for (let i = 0; i < counts[sev] && list.length < 5; i++) list.push(sev);
  }
  while (list.length < 5) list.push("empty");
  return list.map(s => `<span class="d d-${s}">●</span>`).join("");
}

// ============== Resources tab ==============
function renderResources() {
  const mount = document.getElementById("resources-content");
  if (!mount) return;

  const categories = [
    {
      title: "Regulations & Standards",
      items: [
        { name: "ISO/SAE 21434:2021", desc: "Road vehicles — Cybersecurity engineering", url: "https://www.iso.org/standard/70918.html" },
        { name: "UNECE WP.29 Regulation R155", desc: "Cyber security management systems (CSMS) for vehicles", url: "https://unece.org/transport/vehicle-regulations/wp29-world-forum-harmonization-vehicle-regulations" },
        { name: "UNECE WP.29 Regulation R156", desc: "Software update management systems (SUMS)", url: "https://unece.org/transport/vehicle-regulations/wp29-world-forum-harmonization-vehicle-regulations" },
        { name: "AIS-189 (India)", desc: "Indian automotive cybersecurity standard aligned to UN R155", url: "https://bis.gov.in/" },
        { name: "SAE J3061", desc: "Cybersecurity guidebook for cyber-physical vehicle systems", url: "https://www.sae.org/standards/content/j3061_202101/" },
        { name: "ISO 26262", desc: "Functional safety for road vehicles (E/E systems)", url: "https://www.iso.org/standard/68383.html" },
      ],
    },
    {
      title: "CVE & Threat Intelligence",
      items: [
        { name: "NVD — National Vulnerability Database", desc: "NIST's CVE repository with CVSS scores and enrichment", url: "https://nvd.nist.gov/" },
        { name: "MITRE CVE Program", desc: "CVE identification and numbering authority", url: "https://cve.mitre.org/" },
        { name: "Auto-ISAC", desc: "Automotive Information Sharing and Analysis Center", url: "https://automotiveisac.com/" },
        { name: "ENISA — Automotive Good Practices", desc: "EU Agency for Cybersecurity automotive threat landscape", url: "https://www.enisa.europa.eu/topics/iot-and-smart-infrastructures/connected-cars" },
        { name: "CERT/CC Vulnerability Notes", desc: "Carnegie Mellon CERT coordination center advisories", url: "https://www.kb.cert.org/vuls/" },
        { name: "Upstream Security AutoThreat", desc: "Automotive cybersecurity threat intelligence platform", url: "https://upstream.auto/" },
      ],
    },
    {
      title: "Attack Surface & Frameworks",
      items: [
        { name: "STRIDE Threat Model", desc: "Microsoft threat modeling methodology (Spoofing, Tampering, …)", url: "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats" },
        { name: "MITRE ATT&CK for ICS", desc: "Tactics and techniques for ICS/OT environments", url: "https://attack.mitre.org/matrices/ics/" },
        { name: "TARA (Threat Analysis & Risk Assessment)", desc: "ISO 21434 mandated TARA methodology overview", url: "https://www.iso.org/standard/70918.html" },
        { name: "OWASP Top 10 for IoT", desc: "Most critical IoT security risks — applies to connected vehicles", url: "https://owasp.org/www-project-internet-of-things/" },
        { name: "CAN Bus Security Research", desc: "Miller & Valasek Jeep Cherokee remote exploit research", url: "https://illmatics.com/Remote%20Car%20Hacking.pdf" },
      ],
    },
    {
      title: "Tools & Testing",
      items: [
        { name: "CANalyze / SocketCAN", desc: "Linux CAN bus interface tools for ECU testing", url: "https://python-can.readthedocs.io/" },
        { name: "Scapy with CAN extensions", desc: "Packet crafting and injection for CAN/OBD2", url: "https://scapy.net/" },
        { name: "UDS (ISO 14229) Fuzzing", desc: "Unified Diagnostic Services protocol fuzzing resources", url: "https://www.iso.org/standard/55283.html" },
        { name: "V2G / EVCC Security (ISO 15118)", desc: "Vehicle-to-Grid communication protocol security", url: "https://www.iso.org/standard/55366.html" },
        { name: "Automotive Grade Linux (AGL)", desc: "Open source automotive infotainment platform", url: "https://www.automotivelinux.org/" },
      ],
    },
    {
      title: "Learning & Community",
      items: [
        { name: "escar Conference", desc: "Embedded Security in Cars — premier auto cybersec conference", url: "https://www.escar.info/" },
        { name: "DEF CON Car Hacking Village", desc: "Annual automotive security research village", url: "https://www.carhackingvillage.com/" },
        { name: "Auto-ISAC Best Practices", desc: "Seven automotive cybersecurity best practices framework", url: "https://automotiveisac.com/best-practices/" },
        { name: "AUTOCRYPT TechBlog", desc: "Automotive cybersecurity technical articles and research", url: "https://autocrypt.io/blog/" },
      ],
    },
    {
      title: "Quick Reference: CVSS Scoring",
      items: [
        { name: "CVSS v3.1 Specification", desc: "Common Vulnerability Scoring System v3.1 guide — NVD", url: "https://www.first.org/cvss/v3.1/specification-document" },
        { name: "CVSS Calculator", desc: "FIRST.org online CVSS v3.1 / v4.0 scoring calculator", url: "https://www.first.org/cvss/calculator/3.1" },
        { name: "CVSS v4.0 (Latest)", desc: "Next-generation vulnerability scoring with automotive-relevant vectors", url: "https://www.first.org/cvss/v4.0/specification-document" },
        { name: "Attack Vector Taxonomy", desc: "N=Network, A=Adjacent, L=Local, P=Physical — key for automotive", url: "https://nvd.nist.gov/vuln-metrics/cvss" },
      ],
    },
  ];

  let html = `<p class="resources-intro">&#9658; Curated reference list for automotive cybersecurity professionals — standards, threat intel sources, attack surface frameworks, and tooling. All links open external resources.</p>`;
  html += `<div class="resources-grid">`;
  for (const cat of categories) {
    html += `<div class="resource-category">`;
    html += `<h3>${escapeHtml(cat.title)}</h3>`;
    html += `<div class="resource-list">`;
    for (const item of cat.items) {
      html += `<div class="resource-item">
        <a href="${escapeAttr(item.url)}" target="_blank" rel="noreferrer">${escapeHtml(item.name)}</a>
        <span>${escapeHtml(item.desc)}</span>
      </div>`;
    }
    html += `</div></div>`;
  }
  html += `</div>`;
  mount.innerHTML = html;
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
