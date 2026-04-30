// compliance.js
// Renders the compliance matrix tab (ISO 21434, UN R155, UN R156, AIS-189)
// based on the currently filtered CVE set.

export function renderCompliance(cves, complianceMap, mountEl) {
  const standards  = complianceMap.standards;
  const categories = complianceMap.categories;

  // Build clause -> count by walking each CVE's categories.
  // counts[standardId][clauseId] = number of CVEs touching that clause
  const counts = {};
  for (const stdId of Object.keys(standards)) counts[stdId] = {};

  for (const cve of cves) {
    const cveCats = cve.categories || [];
    // Sum unique clauses for this single CVE so one CVE never inflates a clause more than once.
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
        counts[stdId][clauseId] = (counts[stdId][clauseId] || 0) + 1;
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
    in <code>data/compliance_map.json</code>. This is an interpretive aid, not a substitute for a TARA or audit evidence.
  </p>`;

  for (const [stdId, std] of Object.entries(standards)) {
    html += `<div class="standard-block">`;
    html += `<h2>${escapeHtml(std.name)}</h2>`;
    html += `<table class="clause-table"><thead><tr>
      <th style="width:140px;">Clause</th>
      <th>Description</th>
      <th style="width:120px;">Open CVEs</th>
    </tr></thead><tbody>`;
    for (const [clauseId, clauseDesc] of Object.entries(std.clauses)) {
      const n = counts[stdId][clauseId] || 0;
      html += `<tr>
        <td><strong>${escapeHtml(clauseId)}</strong></td>
        <td>${escapeHtml(clauseDesc)}</td>
        <td><span class="${heatClass(n)}">${n}</span></td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  mountEl.innerHTML = html;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
