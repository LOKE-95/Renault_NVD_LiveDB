// compliance.js
// Renders the compliance matrix tab: ISO 21434, UN R155, UN R156, AIS-189.
// Includes per-standard coverage meter, critical-clause highlighting,
// and click-to-filter integration with the main dashboard.

export function renderCompliance(cves, complianceMap, mountEl, opts = {}) {
  const { onClauseClick, activeClause } = opts;
  const standards  = complianceMap.standards;
  const categories = complianceMap.categories;

  // counts[standardId][clauseId] = { total: n, critical: n, high: n }
  const counts = {};
  for (const stdId of Object.keys(standards)) counts[stdId] = {};

  for (const cve of cves) {
    const cveCats = cve.categories || [];
    const touched = {};
    for (const stdId of Object.keys(standards)) touched[stdId] = new Set();

    for (const catId of cveCats) {
      const cat = categories.find(c => c.id === catId);
      if (!cat) continue;
      for (const [stdId, clauseList] of Object.entries(cat.clauses || {})) {
        for (const clauseId of clauseList) {
          touched[stdId].add(clauseId);
        }
      }
    }
    for (const [stdId, clauseSet] of Object.entries(touched)) {
      for (const clauseId of clauseSet) {
        if (!counts[stdId][clauseId]) {
          counts[stdId][clauseId] = { total: 0, critical: 0, high: 0 };
        }
        counts[stdId][clauseId].total += 1;
        if (cve.severity === "CRITICAL") counts[stdId][clauseId].critical += 1;
        if (cve.severity === "HIGH")     counts[stdId][clauseId].high += 1;
      }
    }
  }

  const heatClass = (n) => {
    if (!n) return "heat heat-0";
    if (n <= 2) return "heat heat-1";
    if (n <= 5) return "heat heat-2";
    return "heat heat-3";
  };

  let html = "";
  html += `<p style="color:var(--muted);font-size:13px;margin:0 0 14px;">
    Counts show how many of the currently-filtered CVEs plausibly map to each clause based on category rules
    in <code>data/compliance_map.json</code>. Click any clause to filter the CVE table to that intersection.
    A red left-bar marks clauses with at least one Critical CVE in scope.
  </p>`;

  for (const [stdId, std] of Object.entries(standards)) {
    const totalClauses = Object.keys(std.clauses).length;
    const touchedClauses = Object.keys(counts[stdId]).length;
    const pct = totalClauses ? Math.round((touchedClauses / totalClauses) * 100) : 0;

    html += `<div class="standard-block">`;
    html += `<h2>${escapeHtml(std.name)}</h2>`;
    html += `<div class="coverage-meter">
      <span>Open-CVE coverage: ${touchedClauses} of ${totalClauses} clauses (${pct}%)</span>
      <div class="coverage-bar"><div class="coverage-fill" style="width:${pct}%"></div></div>
    </div>`;
    html += `<table class="clause-table"><thead><tr>
      <th style="width:140px;">Clause</th>
      <th>Description</th>
      <th style="width:120px;">Open CVEs</th>
      <th style="width:90px;">Critical</th>
      <th style="width:80px;">High</th>
    </tr></thead><tbody>`;
    for (const [clauseId, clauseDesc] of Object.entries(std.clauses)) {
      const c = counts[stdId][clauseId] || { total: 0, critical: 0, high: 0 };
      const rowClasses = [];
      if (c.total > 0) rowClasses.push("clickable");
      if (c.critical > 0) rowClasses.push("has-critical");
      if (activeClause && activeClause.standard === stdId && activeClause.clauseId === clauseId) {
        rowClasses.push("active");
      }
      html += `<tr class="${rowClasses.join(" ")}" data-std="${escapeAttr(stdId)}" data-clause="${escapeAttr(clauseId)}">
        <td><strong>${escapeHtml(clauseId)}</strong></td>
        <td>${escapeHtml(clauseDesc)}</td>
        <td><span class="${heatClass(c.total)}">${c.total}</span></td>
        <td>${c.critical > 0 ? `<span class="sev-badge sev-CRITICAL">${c.critical}</span>` : "—"}</td>
        <td>${c.high > 0 ? `<span class="sev-badge sev-HIGH">${c.high}</span>` : "—"}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  mountEl.innerHTML = html;

  if (typeof onClauseClick === "function") {
    mountEl.querySelectorAll("tr.clickable").forEach(tr => {
      tr.addEventListener("click", () => {
        onClauseClick(tr.dataset.std, tr.dataset.clause);
      });
    });
  }
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function escapeAttr(s) {
  return escapeHtml(s);
}
