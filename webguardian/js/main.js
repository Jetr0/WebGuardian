const API = `http://${location.hostname}:5000/api`;

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("attackChart")) loadStats();
  if (document.getElementById("logContainer")) loadLogs();
  if (document.getElementById("wlList")) initWhitelist();
});

// ---------- INDEX ----------
async function loadStats() {
  const stats = await fetchJson(`${API}/stats`);
  const ul = document.getElementById("statsList");
  ul.innerHTML = `
    <li class="list-group-item">Solicitudes totales:
        <strong>${stats.total_requests}</strong></li>
    <li class="list-group-item text-danger">Solicitudes bloqueadas:
        <strong>${stats.blocked_requests}</strong></li>
    <li class="list-group-item">IPs bloqueadas:
        <strong>${stats.blocked_ips}</strong></li>
    <li class="list-group-item">Última solicitud:
        <strong>${stats.last_request || "—"}</strong></li>`;
  renderChart(stats.attacks_by_type);
}

function renderChart(data) {
  const ctx = document.getElementById("attackChart");
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(data),
      datasets: [{ data: Object.values(data) }]
    },
    options: { legend:{display:false}, scales:{y:{beginAtZero:true}} }
  });
}

// ---------- LOGS ----------
async function loadLogs() {
  const logs = await fetchJson(`${API}/logs`);
  const box  = document.getElementById("logContainer");
  box.innerHTML = logs.map(l => `<div class="log-entry">${l}</div>`).join("");
}

// ---------- WHITELIST ----------
function initWhitelist() {
  loadWhitelist();
  document.getElementById("addForm").addEventListener("submit", async e => {
    e.preventDefault();
    const ip = document.getElementById("ipInput").value;
    await fetch(`${API}/whitelist/add`, {
      method:"POST", headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip})
    });
    document.getElementById("ipInput").value="";
    loadWhitelist();
  });
}

async function loadWhitelist() {
  const wl = await fetchJson(`${API}/whitelist`);
  const list = document.getElementById("wlList");
  list.innerHTML = wl.map(ip => `
    <li class="list-group-item d-flex justify-content-between">
      <span>${ip}</span>
      <button class="btn btn-sm btn-outline-danger"
              onclick="removeIp('${ip}')">&times;</button>
    </li>`).join("");
}
async function removeIp(ip) {
  await fetch(`${API}/whitelist/remove/${ip}`);
  loadWhitelist();
}

// ---------- HELPER ----------
async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}
