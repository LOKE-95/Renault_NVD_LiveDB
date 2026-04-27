// TAB SWITCH
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

  document.getElementById('tab-' + name).classList.add('active');
  el.classList.add('active');
}

// 🔥 FALLBACK DATA (YOUR ORIGINAL CORE IDEA PRESERVED)
const FALLBACK_DATA = [
  {id:'CVE-2026-1183', desc:'ADAS spoofing vulnerability', score:9.8},
  {id:'CVE-2026-0847', desc:'OTA remote exploit', score:9.1},
  {id:'CVE-2025-4412', desc:'TCU data leak', score:8.8}
];

// LOAD DATA
async function loadCVEs() {
  try {
    const res = await fetch("data/cve.json");

    if (!res.ok) throw new Error("No live data");

    const data = await res.json();

    const items = data.vulnerabilities || [];

    const parsed = items.map(v => {
      const cve = v.cve;

      return {
        id: cve.id,
        desc: cve.descriptions?.[0]?.value || "",
        score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0
      };
    });

    return parsed.length ? parsed : FALLBACK_DATA;

  } catch (e) {
    console.warn("Using fallback data");
    return FALLBACK_DATA;
  }
}

// RENDER TABLE
function renderTable(data) {
  const tbody = document.getElementById('cve-tbody');

  tbody.innerHTML = data.map(d => `
    <tr>
      <td>${d.id}</td>
      <td>${d.desc}</td>
      <td>${d.score}</td>
    </tr>
  `).join('');
}

// CHART
function renderChart(data) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  data.forEach(d => {
    if (d.score >= 9) counts.critical++;
    else if (d.score >= 7) counts.high++;
    else if (d.score >= 4) counts.medium++;
    else counts.low++;
  });

  new Chart(document.getElementById('chart-sev'), {
    type: 'bar',
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        label: "CVEs",
        data: Object.values(counts)
      }]
    }
  });
}

// SEARCH
function setupSearch(data) {
  document.getElementById('cve-search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();

    const filtered = data.filter(d =>
      d.id.toLowerCase().includes(q) ||
      d.desc.toLowerCase().includes(q)
    );

    renderTable(filtered);
  });
}

// INIT
document.addEventListener("DOMContentLoaded", async () => {
  const data = await loadCVEs();

  renderTable(data);
  renderChart(data);
  setupSearch(data);
});