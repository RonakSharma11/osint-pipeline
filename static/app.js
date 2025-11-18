// static/app.js
const RESULTS_ENDPOINT = "/api/iocs";
const METRICS_ENDPOINT = "/api/metrics";

let page = 1;
let per_page = 25;

// UI elements
const searchEl = document.getElementById("search");
const riskEl = document.getElementById("risk");
const sortEl = document.getElementById("sort");
const orderEl = document.getElementById("order");
const applyBtn = document.getElementById("apply");
const refreshBtn = document.getElementById("refresh");
const prevBtn = document.getElementById("prev");
const nextBtn = document.getElementById("next");
const pageInfo = document.getElementById("page-info");
const perPageEl = document.getElementById("per_page");
const tableBody = document.querySelector("#table tbody");
const detailJson = document.getElementById("detail-json");
const metricsBody = document.getElementById("metrics-body");

// Helpers
function scoreClass(score) {
  if (score >= 75) return "score-high";
  if (score >= 35) return "score-med";
  return "score-low";
}

function formatValue(it) {
  return it.value || it.id || "";
}

async function fetchMetrics() {
  try {
    const r = await fetch(METRICS_ENDPOINT);
    const j = await r.json();
    metricsBody.innerHTML = `
      <div>Total IOCs: <strong>${j.total}</strong></div>
      <div>Risk: H:${j.by_risk.high} M:${j.by_risk.medium} L:${j.by_risk.low}</div>
      <div>Avg score: <strong>${j.avg_score ? j.avg_score.toFixed(2) : "N/A"}</strong></div>
      <div>Top: ${j.top.map(t => `${t.value} (${t.score})`).join(", ")}</div>
    `;
  } catch (e) {
    metricsBody.textContent = "Could not fetch metrics: " + e;
  }
}

async function loadPage() {
  const q = encodeURIComponent(searchEl.value || "");
  const risk = encodeURIComponent(riskEl.value || "");
  const sort = encodeURIComponent(sortEl.value || "");
  const order = encodeURIComponent(orderEl.value || "");
  per_page = parseInt(perPageEl.value || "25");
  const url = `${RESULTS_ENDPOINT}?q=${q}&risk=${risk}&sort=${sort}&order=${order}&page=${page}&per_page=${per_page}`;
  tableBody.innerHTML = "<tr><td colspan='6'>Loading…</td></tr>";
  try {
    const res = await fetch(url);
    const j = await res.json();
    renderTable(j.items);
    pageInfo.textContent = `Page ${j.page} / ${Math.max(1, Math.ceil(j.total / j.per_page))} — ${j.total} total`;
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan='6'>Error loading: ${err}</td></tr>`;
  }
}

function renderTable(items) {
  if (!items || items.length === 0) {
    tableBody.innerHTML = "<tr><td colspan='6'>No results</td></tr>";
    return;
  }
  tableBody.innerHTML = "";
  for (const it of items) {
    const tr = document.createElement("tr");

    const score = it.score || 0;
    const scoreTd = document.createElement("td");
    const sb = document.createElement("span");
    sb.className = `score-badge ${scoreClass(score)}`;
    sb.textContent = score;
    scoreTd.appendChild(sb);
    tr.appendChild(scoreTd);

    const riskTd = document.createElement("td");
    riskTd.textContent = it.risk_bucket || "unknown";
    tr.appendChild(riskTd);

    const typeTd = document.createElement("td");
    typeTd.textContent = it.type || "";
    tr.appendChild(typeTd);

    const valTd = document.createElement("td");
    valTd.textContent = formatValue(it);
    tr.appendChild(valTd);

    const srcTd = document.createElement("td");
    srcTd.textContent = it.source || "";
    tr.appendChild(srcTd);

    const detailsTd = document.createElement("td");
    const btn = document.createElement("button");
    btn.textContent = "View";
    btn.onclick = () => showDetails(it);
    detailsTd.appendChild(btn);
    tr.appendChild(detailsTd);

    tableBody.appendChild(tr);
  }
}

function showDetails(it) {
  detailJson.textContent = JSON.stringify(it, null, 2);
}

// events
applyBtn.onclick = () => { page = 1; loadPage(); fetchMetrics(); };
refreshBtn.onclick = () => { loadPage(); fetchMetrics(); };
prevBtn.onclick = () => { if (page>1) { page--; loadPage(); } };
nextBtn.onclick = () => { page++; loadPage(); };

perPageEl.onchange = () => { page = 1; loadPage(); };

window.onload = () => {
  fetchMetrics();
  loadPage();
};
