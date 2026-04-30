// dashboard.js
// Main dashboard logic: loads JSON, applies filters, renders KPIs/charts/table/ECU breakdown,
// and delegates the compliance matrix to compliance.js.

import { renderCompliance } from "./compliance.js";

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
  selectedOem: "all",
  search: "",
  severity: "all",
  ecuClass: "all",
  charts: {},
};

init().catch(err => {
  console.error(err);
  document.getElementById("last-updated").textContent = "Failed to load data";
});

async function init() {
  const [cveDoc, ecuMap, complianceMap] = await Promise.all([
    fetchJson("data/cves.json"),
    fetchJson("data/ecu_components.json"),
    fetchJson("data/compliance_map.json"),
  ]);

  state.cves = cveDoc.cves || [];
  state.ecuMap = ecuMap;
  state.complianceMap = complianceMap;

  document.getElementById("last-updated").textContent =
    `Last refreshed: ${formatDate(cveDoc.generated_at)} · source: ${cveDoc.source || "n/a"} · ${state.cves.length} CVEs`;

  populateEcuFilter();
  wireOemFilter();
  wireTabs();
  wireCveFilters();

  renderAll();
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
    state.selectedOem = btn.dataset.oem;
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
    // Charts need a re-render after their canvas becomes visible.
    if (tab === "overview") renderCharts();
  });
}

function wireCveFilters() {
  document.getElementById("cve-search").addEventListener("input", (e) => {
    state.search = e.target.value.trim().toLowerCase();
    renderTable();
  });
  document.getElementById("filter-severity").addEventListener("change", (e) => {
    state.severity = e.target.value;
    renderTable();
  });
  document.getElementById("filter-ecu").addEventListener("change", (e) => {
    state.ecuClass = e.target.value;
    renderTable();
  });
}

function filterByOem(cves) {
  if (state.selectedOem === "all") return cves;
  return cves.filter(c => (c.matched_oems || []).includes(state.selectedOem));
}

function filterForTable(cves) {
  return cves.filter(c => {
    if (state.severity !== "all" && (c.severity || "").toUpperCase() !== state.severity) return false;
    if (state.ecuClass !== "all" && c.ecu_class !== state.ecuClass) return false;
    if (state.search) {
      const hay = [
        c.id,
        c.description,
        ...(c.components || []),
        ...(c.matched_keywords || []),
      ].join(" ").toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  });
}

function renderAll() {
  const oemCves = filterByOem(state.cves);
  renderKpis(oemCves);
  renderCharts(oemCves);
  renderTable();
  renderEcuBreakdown(oemCves);
  renderCompliance(oemCves, state.complianceMap, document.getElementById("compliance-content"));
}

function renderKpis(cves) {
  const total = cves.length;
  const crit = cves.filter(c => c.severity === "CRITICAL").length;
  const high = cves.filter(c => c.severity === "HIGH").length;
  const scored = cves.filter(c => typeof c.cvss === "number");
  const avg = scored.length ? (scored.reduce((s, c) => s + c.cvss, 0) / scored.length).toFixed(1) : "—";

  document.getElementById("kpi-total").textContent = total;
  document.getElementById("kpi-critical").textContent = crit;
  document.getElementById("kpi-high").textContent = high;
  document.getElementById("kpi-avg").textContent = avg;
}

function renderCharts(cvesArg) {
  const cves = cvesArg || filterByOem(state.cves);

  // Severity donut
  const sevCounts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  for (const c of cves) {
    const k = (c.severity || "UNKNOWN").toUpperCase();
    sevCounts[k] = (sevCounts[k] || 0) + 1;
  }
  upsertChart("chart-severity", "doughnut", {
    labels: Object.keys(sevCounts),
    datasets: [{
      data: Object.values(sevCounts),
      backgroundColor: Object.keys(sevCounts).map(k => SEV_COLORS[k] || "#8b949e"),
      borderColor: "#161b22",
      borderWidth: 2,
    }],
  }, {
    plugins: { legend: { position: "bottom", labels: { color: "#e6edf3" } } },
  });

  // Trend line by month
  const byMonth = {};
  for (const c of cves) {
    const ym = (c.published || "").slice(0, 7);
    if (!ym) continue;
    byMonth[ym] = (byMonth[ym] || 0) + 1;
  }
  const months = Object.keys(byMonth).sort();
  upsertChart("chart-trend", "line", {
    labels: months,
    datasets: [{
      label: "CVEs",
      data: months.map(m => byMonth[m]),
      borderColor: "#58a6ff",
      backgroundColor: "rgba(88,166,255,0.15)",
      fill: true,
      tension: 0.3,
    }],
  }, {
    scales: {
      x: { ticks: { color: "#8b949e" }, grid: { color: "#2a313c" } },
      y: { ticks: { color: "#8b949e" }, grid: { color: "#2a313c" }, beginAtZero: true, precision: 0 },
    },
    plugins: { legend: { display: false } },
  });

  // Top components bar
  const compCounts = {};
  for (const c of cves) {
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
      borderRadius: 4,
    }],
  }, {
    indexAxis: "y",
    scales: {
      x: { ticks: { color: "#8b949e" }, grid: { color: "#2a313c" }, beginAtZero: true, precision: 0 },
      y: { ticks: { color: "#e6edf3" }, grid: { color: "#2a313c" } },
    },
    plugins: { legend: { display: false } },
  });
}

function upsertChart(canvasId, type, data, options = {}) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (state.charts[canvasId]) {
    state.charts[canvasId].data = data;
    state.charts[canvasId].options = mergeOptions(state.charts[canvasId].options, options);
    state.charts[canvasId].update();
    return;
  }
  state.charts[canvasId] = new Chart(ctx, {
    type, data,
    options: mergeOptions({
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#e6edf3" } } },
    }, options),
  });
}

function mergeOptions(a, b) {
  return { ...a, ...b, plugins: { ...(a.plugins||{}), ...(b.plugins||{}) }, scales: { ...(a.scales||{}), ...(b.scales||{}) } };
}

function renderTable() {
  const oemCves = filterByOem(state.cves);
  const filtered = filterForTable(oemCves);
  document.getElementById("cve-count").textContent = `${filtered.length} of ${oemCves.length} match`;

  const tbody = document.getElementById("cve-tbody");
  tbody.innerHTML = filtered.map(c => `
    <tr>
      <td><a href="${escapeAttr(c.url)}" target="_blank" rel="noreferrer">${escapeHtml(c.id)}</a></td>
      <td><span class="sev-badge sev-${escapeAttr(c.severity || "UNKNOWN")}">${escapeHtml(c.severity || "?")}</span></td>
      <td>${c.cvss ?? "—"}</td>
      <td>${escapeHtml(c.published || "")}</td>
      <td>${(c.matched_oems || []).map(o => `<span class="tag">${escapeHtml(displayOem(o))}</span>`).join("")}</td>
      <td>${escapeHtml(displayEcu(c.ecu_class))}</td>
      <td>${(c.components || []).map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("")}</td>
      <td class="desc">${escapeHtml(truncate(c.description || "", 240))}</td>
    </tr>
  `).join("");
}

function renderEcuBreakdown(cves) {
  const mount = document.getElementById("ecu-breakdown");
  const oems = state.selectedOem === "all"
    ? Object.keys(state.ecuMap)
    : [state.selectedOem];

  let html = "";
  for (const oemId of oems) {
    const oem = state.ecuMap[oemId];
    if (!oem) continue;
    const oemCves = cves.filter(c => (c.matched_oems || []).includes(oemId));
    html += `<div class="oem-block">`;
    html += `<h2>${escapeHtml(oem.display_name)} <span class="tag">${oemCves.length} CVEs</span></h2>`;
    html += `<div class="ecu-grid">`;
    for (const [classId, cls] of Object.entries(oem.ecu_classes || {})) {
      const n = oemCves.filter(c => c.ecu_class === classId).length;
      html += `<div class="ecu-card">
        <h4>${escapeHtml(cls.label)}</h4>
        <div class="count">${n}</div>
        <div class="components">${(cls.components || []).map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("")}</div>
      </div>`;
    }
    html += `</div></div>`;
  }
  mount.innerHTML = html;
}

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
