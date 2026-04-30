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
const viewerCopy = document.getElementById('viewer-copy');

let allowKill = true;
let activeStream = null;

// Decode base64 to a Uint8Array (preserving raw bytes for xterm).
function b64ToBytes(s) {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64ToString(s) {
  return new TextDecoder('utf-8', { fatal: false }).decode(b64ToBytes(s));
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

let term = null;
let fitAddon = null;

function ensureTerminal() {
  if (term) return;
  term = new Terminal({
    convertEol: true,
    cursorBlink: false,
    disableStdin: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    fontSize: 13,
    scrollback: 5000,
    theme: { background: '#000000', foreground: '#eeeeee' },
  });
  if (typeof FitAddon !== 'undefined') {
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
  }
  term.open(viewerOutput);
}

function termWriteText(s) {
  ensureTerminal();
  term.write(s);
}

function openStream(s) {
  closeStream();
  viewerTitle.textContent = `${s.instance_id} • ${s.id}`;
  viewer.classList.add('active');
  ensureTerminal();
  term.reset();
  if (fitAddon) {
    requestAnimationFrame(() => { try { fitAddon.fit(); } catch {} });
  }
  const url = `/api/v1/sessions/${encodeURIComponent(s.instance_id)}/${encodeURIComponent(s.id)}/stream`;
  const es = new EventSource(url);
  activeStream = es;
  es.addEventListener('header', (e) => {
    try {
      const h = JSON.parse(e.data);
      termWriteText(`\x1b[2m[stream started, ${h.width}x${h.height}, channel ${h.channel_id}]\x1b[0m\r\n`);
      if (h.width && h.height) {
        try { term.resize(h.width, h.height); } catch {}
      }
    } catch {}
  });
  es.addEventListener('o', (e) => appendData(e));
  es.addEventListener('r', (e) => {
    try {
      const r = JSON.parse(e.data);
      const dims = b64ToString(r.data);
      termWriteText(`\r\n\x1b[2m[resize ${dims}]\x1b[0m\r\n`);
      const m = /^\s*(\d+)[xX](\d+)\s*$/.exec(dims);
      if (m) {
        try { term.resize(parseInt(m[1], 10), parseInt(m[2], 10)); } catch {}
      }
    } catch {}
  });
  es.addEventListener('error', (e) => {
    if (e.data) {
      try { termWriteText('\r\n\x1b[31m[stream error] ' + JSON.parse(e.data).error + '\x1b[0m\r\n'); } catch {}
    }
  });
  es.onerror = () => { /* EventSource will auto-reconnect; nothing to do */ };
}

function appendData(e) {
  try {
    const ev = JSON.parse(e.data);
    ensureTerminal();
    term.write(b64ToBytes(ev.data));
  } catch {}
}

function closeStream() {
  if (activeStream) { activeStream.close(); activeStream = null; }
  viewer.classList.remove('active');
}

window.addEventListener('resize', () => {
  if (fitAddon && viewer.classList.contains('active')) {
    try { fitAddon.fit(); } catch {}
  }
});

viewerClose.addEventListener('click', closeStream);
viewerCopy.addEventListener('click', async () => {
  if (!term) return;
  let text = term.getSelection();
  if (!text) {
    const buf = term.buffer.active;
    const lines = [];
    for (let i = 0; i < buf.length; i++) {
      const line = buf.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    while (lines.length && lines[lines.length - 1] === '') lines.pop();
    text = lines.join('\n');
  }
  const original = viewerCopy.textContent;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    viewerCopy.textContent = 'copied';
  } catch (e) {
    viewerCopy.textContent = 'copy failed';
  }
  setTimeout(() => { viewerCopy.textContent = original; }, 1200);
});
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
