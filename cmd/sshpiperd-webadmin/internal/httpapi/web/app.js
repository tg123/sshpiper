// Minimal vanilla-JS client for the sshpiperd-webadmin HTTP API.
// Polls /api/v1/sessions every few seconds and renders a table; opens an
// SSE stream into a simple <pre> viewer when "view" is clicked.

const meta = document.getElementById('meta');
const instancesBody = document.querySelector('#instances tbody');
const sessionsBody = document.querySelector('#sessions tbody');
const errorsBox = document.getElementById('errors');
const emptyBox = document.getElementById('empty');
const viewer = document.getElementById('viewer');
const viewerOutput = document.getElementById('viewer-output');
const viewerTitle = document.getElementById('viewer-title');
const viewerClose = document.getElementById('viewer-close');

let allowKill = true;
let activeStream = null;

// Decode base64 to a Uint8Array, then to a UTF-8 string.
function b64ToString(s) {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function fmtSince(unixSec) {
  if (!unixSec) return '';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}

async function loadVersion() {
  try {
    const r = await fetch('/api/v1/version');
    const j = await r.json();
    allowKill = !!j.allow_kill;
    meta.textContent = j.version + (allowKill ? '' : ' • read-only');
  } catch (e) {
    meta.textContent = '(version unavailable)';
  }
}

async function loadInstances() {
  try {
    const r = await fetch('/api/v1/instances');
    const j = await r.json();
    instancesBody.innerHTML = '';
    for (const i of j.instances || []) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(i.id)}</td>
        <td>${escapeHtml(i.addr)}</td>
        <td>${escapeHtml(i.ssh_addr || '')}</td>
        <td>${escapeHtml(i.version || '')}</td>
        <td>${fmtSince(i.started_at)}</td>`;
      instancesBody.appendChild(tr);
    }
  } catch (e) {
    instancesBody.innerHTML = `<tr><td colspan="5">${escapeHtml(String(e))}</td></tr>`;
  }
}

async function loadSessions() {
  try {
    const r = await fetch('/api/v1/sessions');
    const j = await r.json();
    sessionsBody.innerHTML = '';
    const rows = j.sessions || [];
    emptyBox.style.display = rows.length ? 'none' : '';
    for (const s of rows) {
      const tr = document.createElement('tr');
      if (!allowKill) tr.classList.add('kill-disabled');
      tr.innerHTML = `<td>${escapeHtml(s.instance_id)}</td>
        <td><code>${escapeHtml(s.id)}</code></td>
        <td>${fmtSince(s.started_at)}</td>
        <td>${escapeHtml(s.downstream_user)}@${escapeHtml(s.downstream_addr)}</td>
        <td>${escapeHtml(s.upstream_user)}@${escapeHtml(s.upstream_addr)}</td>
        <td><button class="view" ${s.streamable ? '' : 'disabled title="no active shell channel"'}>view</button></td>
        <td><button class="kill">kill</button></td>`;
      tr.querySelector('button.view').addEventListener('click', () => openStream(s));
      tr.querySelector('button.kill').addEventListener('click', () => killSession(s));
      sessionsBody.appendChild(tr);
    }
    errorsBox.textContent = (j.errors || []).join('\n');
  } catch (e) {
    errorsBox.textContent = String(e);
  }
}

async function killSession(s) {
  if (!confirm(`Kill session ${s.id} on ${s.instance_id}?`)) return;
  try {
    const r = await fetch(`/api/v1/sessions/${encodeURIComponent(s.instance_id)}/${encodeURIComponent(s.id)}`, { method: 'DELETE' });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      alert('kill failed: ' + (j.error || r.status));
      return;
    }
    loadSessions();
  } catch (e) {
    alert(String(e));
  }
}

function openStream(s) {
  closeStream();
  viewerTitle.textContent = `${s.instance_id} • ${s.id}`;
  viewerOutput.textContent = '';
  viewer.classList.add('active');
  const url = `/api/v1/sessions/${encodeURIComponent(s.instance_id)}/${encodeURIComponent(s.id)}/stream`;
  const es = new EventSource(url);
  activeStream = es;
  es.addEventListener('header', (e) => {
    try {
      const h = JSON.parse(e.data);
      viewerOutput.textContent += `[stream started, ${h.width}x${h.height}, channel ${h.channel_id}]\n`;
    } catch {}
  });
  es.addEventListener('o', (e) => appendData(e));
  es.addEventListener('i', (e) => appendData(e));
  es.addEventListener('r', (e) => {
    try {
      const r = JSON.parse(e.data);
      const dims = b64ToString(r.data);
      viewerOutput.textContent += `\n[resize ${dims}]\n`;
    } catch {}
  });
  es.addEventListener('error', (e) => {
    if (e.data) {
      try { viewerOutput.textContent += '\n[stream error] ' + JSON.parse(e.data).error + '\n'; } catch {}
    }
  });
  es.onerror = () => { /* EventSource will auto-reconnect; nothing to do */ };
}

function appendData(e) {
  try {
    const ev = JSON.parse(e.data);
    viewerOutput.textContent += b64ToString(ev.data);
    viewerOutput.scrollTop = viewerOutput.scrollHeight;
  } catch {}
}

function closeStream() {
  if (activeStream) { activeStream.close(); activeStream = null; }
  viewer.classList.remove('active');
}

viewerClose.addEventListener('click', closeStream);
document.getElementById('refresh').addEventListener('click', loadSessions);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

(async () => {
  await loadVersion();
  await loadInstances();
  await loadSessions();
  setInterval(loadSessions, 5000);
  setInterval(loadInstances, 30000);
})();
