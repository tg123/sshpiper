// Vanilla-JS client for the sshpiperd-webadmin HTTP API.
// Polls /api/v1/sessions and /api/v1/instances, renders sortable tables,
// and opens a <dialog>-based xterm.js viewer for each session's SSE stream.

import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import './style.css';

const $ = (id) => document.getElementById(id);

const meta = $('meta');
const instancesBody = document.querySelector('#instances tbody');
const instancesMeta = $('instances-meta');
const sessionsBody = document.querySelector('#sessions tbody');
const sessionsTable = $('sessions');
const errorsBox = $('errors');
const emptyBox = $('empty');
const filterInput = $('filter');
const autoRefreshChk = $('autorefresh');
const refreshBtn = $('refresh');
const toasts = $('toasts');

const viewer = $('viewer');
const viewerOutput = $('viewer-output');
const viewerTitle = $('viewer-title');
const viewerClose = $('viewer-close');
const viewerCopy = $('viewer-copy');
const viewerRecord = $('viewer-record');

let allowKill = true;
let activeStream = null;
let lastSessions = [];
let sessionErrors = [];
let sortKey = 'started_at';
let sortDir = 'desc'; // 'asc' | 'desc'
let filterText = '';
let autoRefreshTimer = null;
let timestampTicker = null;

// ---------- helpers ----------

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

// Inspect the latest sessions error messages and try to extract instance
// identifiers (the aggregator prefixes errors with "<instance>:"). Returns
// `{ ids, addrs }`: two parallel Sets covering the same instances, where
// `ids.size` is the canonical degraded-instance count and `addrs` is only a
// lookup helper for matching rows that don't carry an ID.
function degradedInstances() {
  const ids = new Set();
  const addrs = new Set();
  for (const msg of sessionErrors) {
    // AggregatorError formats as: "admin instance <id> (<addr>): <err>".
    const m = /^admin instance (\S+) \(([^)]+)\):/.exec(msg || '');
    if (m) {
      ids.add(m[1]);
      addrs.add(m[2]);
    }
  }
  return { ids, addrs };
}

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

function showToast(message, kind = 'info', timeout = 4000) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = message;
  toasts.appendChild(el);
  if (timeout > 0) {
    setTimeout(() => {
      el.style.transition = 'opacity 0.25s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 280);
    }, timeout);
  }
  return el;
}

async function copyToClipboard(text) {
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
    return true;
  } catch (e) {
    return false;
  }
}

// ---------- version / instances ----------

async function loadVersion() {
  try {
    const r = await fetch('/api/v1/version');
    const j = await r.json();
    allowKill = !!j.allow_kill;
    meta.textContent = 'v' + j.version + (allowKill ? '' : ' • read-only');
  } catch (e) {
    meta.textContent = '(version unavailable)';
  }
}

async function loadInstances() {
  let payload;
  try {
    const r = await fetch('/api/v1/instances');
    payload = await r.json();
  } catch (e) {
    instancesBody.innerHTML = `<tr><td colspan="6">${escapeHtml(String(e))}</td></tr>`;
    return;
  }
  const list = payload.instances || [];
  // The aggregator only returns instances that responded to ServerInfo,
  // so every entry here is by definition reachable. We mark instances
  // mentioned in the latest sessions error list as "degraded".
  const degraded = degradedInstances();
  instancesMeta.textContent = `${list.length} reachable`
    + (degraded.ids.size ? ` • ${degraded.ids.size} degraded` : '');
  instancesBody.innerHTML = '';
  for (const i of list) {
    const isDegraded = degraded.ids.has(i.id) || degraded.addrs.has(i.addr);
    const tr = document.createElement('tr');
    const idCell = `<code class="copy" data-copy="${escapeHtml(i.id)}" title="copy">${escapeHtml(i.id)}</code>`;
    const addrCell = `<code class="copy" data-copy="${escapeHtml(i.addr)}" title="copy">${escapeHtml(i.addr)}</code>`;
    const sshCell = i.ssh_addr
      ? `<code class="copy" data-copy="${escapeHtml(i.ssh_addr)}" title="copy">${escapeHtml(i.ssh_addr)}</code>`
      : '';
    tr.innerHTML = `<td>${idCell}</td>
      <td>${addrCell}</td>
      <td>${sshCell}</td>
      <td><span class="mono">${escapeHtml(i.version || '')}</span></td>
      <td data-since="${i.started_at || ''}">${fmtSince(i.started_at)}</td>
      <td><span class="pill ${isDegraded ? 'offline' : 'online'}">${isDegraded ? 'degraded' : 'online'}</span></td>`;
    instancesBody.appendChild(tr);
  }
  updateStats({ instances: list.length, degraded: degraded.ids.size });
}

// ---------- stat cards ----------

const statRefs = {
  instances:  () => document.getElementById('stat-instances'),
  reachable:  () => document.getElementById('stat-reachable'),
  sessions:   () => document.getElementById('stat-sessions'),
  streamable: () => document.getElementById('stat-streamable'),
  upstreams:  () => document.getElementById('stat-upstreams'),
  users:      () => document.getElementById('stat-users'),
  degraded:   () => document.getElementById('stat-degraded'),
};

function updateStats(partial) {
  if (partial.instances !== undefined) {
    setText(statRefs.instances(), partial.instances);
    setText(statRefs.reachable(), partial.instances);
  }
  if (partial.degraded !== undefined) {
    setText(statRefs.degraded(), partial.degraded);
  }
  if (partial.sessions !== undefined) {
    setText(statRefs.sessions(), partial.sessions);
  }
  if (partial.streamable !== undefined) {
    setText(statRefs.streamable(), partial.streamable);
  }
  if (partial.upstreams !== undefined) {
    setText(statRefs.upstreams(), partial.upstreams);
  }
  if (partial.users !== undefined) {
    setText(statRefs.users(), partial.users);
  }
}

function setText(el, v) {
  if (!el) return;
  const s = String(v);
  if (el.textContent !== s) el.textContent = s;
}

// ---------- sessions ----------

function sessionMatches(s, q) {
  if (!q) return true;
  const hay = [
    s.instance_id, s.id,
    s.downstream_user, s.downstream_addr,
    s.upstream_user, s.upstream_addr,
  ].join(' ').toLowerCase();
  return hay.includes(q);
}

function sortValue(s, key) {
  switch (key) {
    case 'started_at': return s.started_at || 0;
    case 'instance_id': return (s.instance_id || '').toLowerCase();
    case 'id': return (s.id || '').toLowerCase();
    case 'downstream': return `${s.downstream_user}@${s.downstream_addr}`.toLowerCase();
    case 'upstream': return `${s.upstream_user}@${s.upstream_addr}`.toLowerCase();
    default: return 0;
  }
}

function renderSessions() {
  const q = filterText.trim().toLowerCase();
  const rows = lastSessions.filter((s) => sessionMatches(s, q));
  rows.sort((a, b) => {
    const av = sortValue(a, sortKey);
    const bv = sortValue(b, sortKey);
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  emptyBox.style.display = rows.length ? 'none' : '';
  if (!rows.length && lastSessions.length && q) {
    emptyBox.textContent = `No sessions match "${q}".`;
  } else {
    emptyBox.textContent = 'No sessions.';
  }

  sessionsBody.innerHTML = '';
  for (const s of rows) {
    const tr = document.createElement('tr');
    if (!allowKill) tr.classList.add('kill-disabled');
    const idCell = `<code class="copy" data-copy="${escapeHtml(s.id)}" title="copy">${escapeHtml(s.id)}</code>`;
    const dCell = `<code class="copy" data-copy="${escapeHtml(s.downstream_user + '@' + s.downstream_addr)}" title="copy">${escapeHtml(s.downstream_user)}@${escapeHtml(s.downstream_addr)}</code>`;
    const uCell = `<code class="copy" data-copy="${escapeHtml(s.upstream_user + '@' + s.upstream_addr)}" title="copy">${escapeHtml(s.upstream_user)}@${escapeHtml(s.upstream_addr)}</code>`;
    tr.innerHTML = `<td>${escapeHtml(s.instance_id)}</td>
      <td>${idCell}</td>
      <td data-since="${s.started_at || ''}">${fmtSince(s.started_at)}</td>
      <td>${dCell}</td>
      <td>${uCell}</td>
      <td><div class="row-actions">
        <button class="view btn btn-ghost" type="button" ${s.streamable ? '' : 'disabled title="no active shell channel"'}>view</button>
        <button class="kill btn btn-danger" type="button">kill</button>
      </div></td>`;
    tr.querySelector('button.view').addEventListener('click', () => openStream(s));
    tr.querySelector('button.kill').addEventListener('click', () => killSession(s));
    sessionsBody.appendChild(tr);
  }

  errorsBox.textContent = sessionErrors.join('\n');

  const upstreams = new Set();
  const users = new Set();
  let streamable = 0;
  for (const s of lastSessions) {
    if (s.upstream_addr) upstreams.add(s.upstream_addr);
    if (s.downstream_user) users.add(s.downstream_user);
    if (s.streamable) streamable++;
  }
  updateStats({
    sessions: lastSessions.length,
    streamable,
    upstreams: upstreams.size,
    users: users.size,
    degraded: degradedInstances().ids.size,
  });

  // Refresh sort indicator classes.
  for (const th of sessionsTable.querySelectorAll('th.sortable')) {
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.dataset.sort === sortKey) {
      th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
    }
  }
}

async function loadSessions() {
  try {
    const r = await fetch('/api/v1/sessions');
    const j = await r.json();
    lastSessions = j.sessions || [];
    sessionErrors = j.errors || [];
    renderSessions();
  } catch (e) {
    errorsBox.textContent = String(e);
  }
}

async function killSession(s) {
  if (!confirm(`Kill session ${s.id} on ${s.instance_id}?`)) return;
  try {
    const r = await fetch(
      `/api/v1/sessions/${encodeURIComponent(s.instance_id)}/${encodeURIComponent(s.id)}`,
      { method: 'DELETE' },
    );
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      showToast('Kill failed: ' + (j.error || r.status), 'error');
      return;
    }
    const j = await r.json().catch(() => ({}));
    showToast(j.killed ? `Killed ${s.id}` : `Session ${s.id} not found`, j.killed ? 'success' : 'info');
    loadSessions();
  } catch (e) {
    showToast(String(e), 'error');
  }
}

// ---------- asciicast recorder ----------
//
// Captures the active SSE stream as an asciicast v2 file
// (https://docs.asciinema.org/manual/asciicast/v2/) entirely on the
// browser side. Each recorded "o" event is the base64-decoded payload
// from the server, written verbatim into the cast.

const recorder = {
  active: false,
  startMs: 0,
  width: 80,
  height: 24,
  events: [],         // [tSec, "o"|"r", string]
  sessionLabel: '',
};

function recorderReset() {
  recorder.active = false;
  recorder.startMs = 0;
  recorder.events = [];
  recorder.sessionLabel = '';
}

function updateRecordButton() {
  if (!viewerRecord) return;
  const span = viewerRecord.querySelector('span');
  const use = viewerRecord.querySelector('use');
  if (recorder.active) {
    viewerRecord.classList.add('recording');
    if (span) span.textContent = 'stop';
    if (use) use.setAttribute('href', '#i-stop');
    viewerRecord.title = 'Stop recording and download asciicast';
  } else {
    viewerRecord.classList.remove('recording');
    if (span) span.textContent = 'record';
    if (use) use.setAttribute('href', '#i-rec');
    viewerRecord.title = 'Start recording (asciicast v2)';
  }
}

function startRecording(initialDims) {
  recorder.active = true;
  recorder.startMs = performance.now();
  recorder.events = [];
  if (initialDims) {
    if (initialDims.width)  recorder.width  = initialDims.width;
    if (initialDims.height) recorder.height = initialDims.height;
  }
  updateRecordButton();
  showToast('Recording started', 'success', 1800);
}

function recordOutput(str) {
  if (!recorder.active || !str) return;
  const t = (performance.now() - recorder.startMs) / 1000;
  recorder.events.push([t, 'o', str]);
}

function recordResize(w, h) {
  if (!recorder.active) return;
  const t = (performance.now() - recorder.startMs) / 1000;
  // asciicast v2 "r" event: payload is "<cols>x<rows>".
  recorder.events.push([t, 'r', `${w}x${h}`]);
}

function stopRecording(reason) {
  if (!recorder.active) return;
  const events = recorder.events;
  const header = {
    version: 2,
    width: recorder.width,
    height: recorder.height,
    timestamp: Math.floor(Date.now() / 1000 - (performance.now() - recorder.startMs) / 1000),
    env: { TERM: 'xterm-256color', SHELL: '/bin/sh' },
    title: recorder.sessionLabel || 'sshpiperd session',
  };
  const lines = [JSON.stringify(header)];
  for (const ev of events) lines.push(JSON.stringify(ev));
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'application/x-asciicast' });
  const safe = (recorder.sessionLabel || 'session').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 80);
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const name = `${safe || 'session'}-${ts}.cast`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);

  const note = events.length === 0 ? 'Recording saved (empty)' : `Recording saved (${events.length} events)`;
  showToast(reason ? `${note} — ${reason}` : note, 'success', 2400);
  recorderReset();
  updateRecordButton();
}

// ---------- terminal viewer ----------

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
  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(viewerOutput);
}

function termWriteText(s) {
  ensureTerminal();
  term.write(s);
}

function openStream(s) {
  closeStream();
  viewerTitle.textContent = `${s.instance_id} • ${s.id}`;
  recorder.sessionLabel = `${s.instance_id}-${s.id}`;
  if (typeof viewer.showModal === 'function') {
    viewer.showModal();
  } else {
    viewer.setAttribute('open', '');
  }
  ensureTerminal();
  term.reset();
  if (fitAddon) {
    requestAnimationFrame(() => { try { fitAddon.fit(); } catch (e) { /* ignore */ } });
  }
  const url = `/api/v1/sessions/${encodeURIComponent(s.instance_id)}/${encodeURIComponent(s.id)}/stream`;
  const es = new EventSource(url);
  activeStream = es;
  es.addEventListener('header', (e) => {
    try {
      const h = JSON.parse(e.data);
      termWriteText(`\x1b[2m[stream started, ${h.width}x${h.height}, channel ${h.channel_id}]\x1b[0m\r\n`);
      if (h.width && h.height) {
        try { term.resize(h.width, h.height); } catch (err) { /* ignore */ }
      }
      if (h.width)  recorder.width  = h.width;
      if (h.height) recorder.height = h.height;
    } catch (err) { /* ignore */ }
  });
  es.addEventListener('o', (e) => appendData(e));
  es.addEventListener('r', (e) => {
    try {
      const r = JSON.parse(e.data);
      const dims = b64ToString(r.data);
      termWriteText(`\r\n\x1b[2m[resize ${dims}]\x1b[0m\r\n`);
      const m = /^\s*(\d+)[xX](\d+)\s*$/.exec(dims);
      if (m) {
        const w = parseInt(m[1], 10);
        const h = parseInt(m[2], 10);
        try { term.resize(w, h); } catch (err) { /* ignore */ }
        recordResize(w, h);
      }
    } catch (err) { /* ignore */ }
  });
  es.addEventListener('error', (e) => {
    if (e.data) {
      try { termWriteText('\r\n\x1b[31m[stream error] ' + JSON.parse(e.data).error + '\x1b[0m\r\n'); } catch (err) { /* ignore */ }
    }
  });
  es.onerror = () => { /* EventSource will auto-reconnect; nothing to do */ };
}

function appendData(e) {
  try {
    const ev = JSON.parse(e.data);
    ensureTerminal();
    const bytes = b64ToBytes(ev.data);
    term.write(bytes);
    if (recorder.active) {
      recordOutput(new TextDecoder('utf-8', { fatal: false }).decode(bytes));
    }
  } catch (err) { /* ignore */ }
}

function closeStream() {
  if (recorder.active) stopRecording('stream closed');
  if (activeStream) { activeStream.close(); activeStream = null; }
  if (viewer.open) {
    if (typeof viewer.close === 'function') viewer.close();
    else viewer.removeAttribute('open');
  } else {
    viewer.removeAttribute('open');
  }
}

// ---------- ticking timestamps ----------

function tickTimestamps() {
  const cells = document.querySelectorAll('td[data-since]');
  for (const td of cells) {
    const sec = parseInt(td.getAttribute('data-since'), 10);
    if (sec > 0) td.textContent = fmtSince(sec);
  }
}

// ---------- auto-refresh control ----------

function setAutoRefresh(on) {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  if (on) {
    autoRefreshTimer = setInterval(() => {
      loadSessions();
    }, 5000);
  }
}

// ---------- event wiring ----------

filterInput.addEventListener('input', () => {
  filterText = filterInput.value;
  renderSessions();
});

autoRefreshChk.addEventListener('change', () => {
  setAutoRefresh(autoRefreshChk.checked);
});

refreshBtn.addEventListener('click', () => {
  loadSessions();
  loadInstances();
});

for (const th of sessionsTable.querySelectorAll('th.sortable')) {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortKey = key;
      // Default direction: started_at descending, others ascending.
      sortDir = key === 'started_at' ? 'desc' : 'asc';
    }
    renderSessions();
  });
}

// Click-to-copy on any <code class="copy">.
document.body.addEventListener('click', async (e) => {
  const target = e.target.closest('code.copy');
  if (!target) return;
  const text = target.dataset.copy || target.textContent;
  if (await copyToClipboard(text)) {
    showToast('Copied: ' + text, 'success', 1800);
  } else {
    showToast('Copy failed', 'error');
  }
});

window.addEventListener('resize', () => {
  if (fitAddon && viewer.open) {
    try { fitAddon.fit(); } catch (e) { /* ignore */ }
  }
});

viewerClose.addEventListener('click', closeStream);
viewer.addEventListener('close', () => {
  if (recorder.active) stopRecording('viewer closed');
  if (activeStream) { activeStream.close(); activeStream = null; }
});
viewer.addEventListener('cancel', (e) => {
  // Allow ESC to close (default), but make sure stream is torn down.
  if (recorder.active) stopRecording('viewer closed');
  if (activeStream) { activeStream.close(); activeStream = null; }
  // Don't preventDefault — let the browser close the dialog.
});

if (viewerRecord) {
  viewerRecord.addEventListener('click', () => {
    if (recorder.active) {
      stopRecording();
    } else {
      startRecording({ width: recorder.width, height: recorder.height });
    }
  });
  updateRecordButton();
}

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
  // Update only the label span so the SVG icon is preserved.
  const label = viewerCopy.querySelector('span') || viewerCopy;
  const original = label.textContent;
  label.textContent = (await copyToClipboard(text)) ? 'copied' : 'copy failed';
  setTimeout(() => { label.textContent = original; }, 1200);
});

// ---------- bootstrap ----------

(async () => {
  await loadVersion();
  await loadInstances();
  await loadSessions();
  setAutoRefresh(autoRefreshChk.checked);
  setInterval(loadInstances, 30000);
  timestampTicker = setInterval(tickTimestamps, 1000);
})();
